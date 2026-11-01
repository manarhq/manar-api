import { createHash } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { BillingService } from '../billing/billing.service';
import { EntitlementsService } from '../billing/entitlements.service';
import { StripeGateway } from '../billing/stripe.gateway';
import type { AppConfig } from '../config/env.validation';
import { ControlPrismaService } from '../database/control-prisma.service';
import {
  ContactEmailService,
  isPlaceholderEmail,
} from '../contact/contact-email.service';
import { GrowthAuditService } from './growth-audit.service';
import { growthSetting } from './growth.config';
import { isDisposableDomain, isConsumerDomain } from './disposable';

export interface LaunchOfferCounter {
  enabled: boolean;
  total: number;
  claimed: number;
  remaining: number;
}

const COUNTER_TTL_MS = 15_000;
const sha = (prefix: string, v: string) =>
  createHash('sha256').update(`${prefix}${v}`).digest('hex');
const deviceHash = (machineId: string) =>
  createHash('sha256').update(`manar-launch-device:${machineId}`).digest('hex');

/**
 * Launch offer: the first N personal sign-ups that add a device get Pro for 3 months, no card.
 *
 * Stripe-correct form: a Pro subscription with `trial_end` and `missing_payment_method: cancel`.
 * A 100%-off coupon would still raise a real invoice in month 4 against a customer with no card
 * (past_due, dunning); a trial ends cleanly into "cancelled unless a card was added", and Stripe
 * sends `customer.subscription.trial_will_end` three days ahead.
 *
 * Slots: claims are counted and inserted inside one transaction holding `pg_advisory_xact_lock`,
 * so N parallel registrations cannot pass the check together; the unique indexes on person
 * (issuer, subject), device hash and workspace are the backstop.
 */
@Injectable()
export class LaunchOfferService {
  private readonly logger = new Logger(LaunchOfferService.name);
  private cached?: { at: number; value: LaunchOfferCounter };

  constructor(
    private readonly control: ControlPrismaService,
    private readonly config: ConfigService<AppConfig, true>,
    private readonly stripe: StripeGateway,
    private readonly billing: BillingService,
    private readonly entitlements: EntitlementsService,
    private readonly audit: GrowthAuditService,
    private readonly contact: ContactEmailService,
  ) {}

  private get enabled(): boolean {
    return (
      growthSetting(this.config, 'LAUNCH_OFFER_ENABLED') === 'true' &&
      this.stripe.configured &&
      !!this.stripe.price('PRO_MONTHLY')
    );
  }

  /** Public counter, cached a few seconds so the landing page cannot load the database. */
  async counter(): Promise<LaunchOfferCounter> {
    if (this.cached && Date.now() - this.cached.at < COUNTER_TTL_MS)
      return this.cached.value;
    const total = growthSetting(this.config, 'LAUNCH_OFFER_SLOTS');
    const claimed = this.enabled
      ? await this.control.launchOfferClaim.count()
      : 0;
    const value = {
      enabled: this.enabled && claimed < total,
      total,
      claimed: Math.min(claimed, total),
      remaining: Math.max(0, total - claimed),
    };
    this.cached = { at: Date.now(), value };
    return value;
  }

  /**
   * Called after a device was registered AND approved in a workspace. Best effort: it never
   * throws, so a billing problem cannot fail an install. Returns true when Pro was granted.
   */
  async onDeviceRegistered(
    tenantId: string,
    device: DeviceFacts,
  ): Promise<boolean> {
    try {
      return await this.claim(tenantId, device);
    } catch (error) {
      this.logger.error(
        `launch offer failed for ${tenantId}: ${String(error)}`,
      );
      return false;
    }
  }

  async claim(tenantId: string, device: DeviceFacts): Promise<boolean> {
    if (!this.enabled) return false;
    const tenant = await this.control.tenant.findUnique({
      where: { id: tenantId },
    });
    if (
      !tenant ||
      tenant.kind !== 'PERSONAL' ||
      tenant.status !== 'ACTIVE' ||
      !tenant.ownerIssuer ||
      !tenant.ownerSubject
    )
      return false;
    const current = await this.control.tenantEntitlement.findUnique({
      where: { tenantId },
    });
    if (current?.stripeSubscriptionId || (current && current.plan !== 'free'))
      return false;

    const issuer = tenant.ownerIssuer;
    const subject = tenant.ownerSubject;
    // Who is this? A Microsoft or GitHub account is a real identity. Otherwise (email link) the
    // person needs a verified contact email on a domain that is not a throwaway mailbox service.
    const [idp, email] = await Promise.all([
      this.contact.idpOf(issuer, subject),
      this.contact.verified(issuer, subject),
    ]);
    const domain =
      email && !isPlaceholderEmail(email)
        ? email.split('@')[1]!.toLowerCase()
        : null;
    const strong = idp === 'microsoft' || idp === 'github';
    if (!strong && (!domain || isDisposableDomain(domain))) return false;
    if (domain && isDisposableDomain(domain)) return false;

    const slots = growthSetting(this.config, 'LAUNCH_OFFER_SLOTS');
    const domainCap = growthSetting(
      this.config,
      'LAUNCH_OFFER_DOMAIN_DAILY_CAP',
    );
    const ipCap = growthSetting(this.config, 'LAUNCH_OFFER_IP_DAILY_CAP');
    const dev = deviceHash(device.machineId);
    // The TPM endorsement key survives a reinstall and a changed machine id, so it counts when known.
    const ek = device.ekFingerprint
      ? sha('manar-launch-ek:', device.ekFingerprint)
      : null;
    const ipHash = device.ip ? sha('manar-launch-ip:', device.ip) : null;
    const since = new Date(Date.now() - 86_400_000);
    const claim = await this.control.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext('launch-offer'))`;
      const taken = await tx.launchOfferClaim.findFirst({
        where: {
          OR: [
            { issuer, subject },
            { deviceHash: dev },
            { tenantId },
            ...(ek ? [{ ekHash: ek }] : []),
          ],
        },
      });
      if (taken) return null;
      if ((await tx.launchOfferClaim.count()) >= slots) return null;
      if (domain && !isConsumerDomain(domain)) {
        const n = await tx.launchOfferClaim.count({
          where: { emailDomain: domain, claimedAt: { gt: since } },
        });
        if (n >= domainCap) return null;
      }
      if (ipHash) {
        const n = await tx.launchOfferClaim.count({
          where: { ipHash, claimedAt: { gt: since } },
        });
        if (n >= ipCap) return null;
      }
      return tx.launchOfferClaim.create({
        data: {
          issuer,
          subject,
          tenantId,
          deviceHash: dev,
          ekHash: ek,
          emailDomain: domain,
          ipHash,
        },
      });
    });
    if (!claim) return false;
    this.cached = undefined;

    try {
      const months = growthSetting(this.config, 'LAUNCH_OFFER_MONTHS');
      const customer = await this.billing.ensureCustomer(
        tenantId,
        email ?? undefined,
      );
      // From the claim time, not from now: a retry sends identical parameters.
      const end = new Date(claim.claimedAt);
      end.setUTCMonth(end.getUTCMonth() + months);
      const stripe = this.stripe.client();
      // A subscription made by an earlier attempt that died before we recorded it is adopted.
      const prior = (
        await stripe.subscriptions.list({ customer, status: 'all', limit: 20 })
      ).data.find(
        (x) =>
          x.metadata?.launchOffer === 'true' &&
          ['trialing', 'active', 'past_due'].includes(x.status),
      );
      const sub =
        prior ??
        (await stripe.subscriptions.create(
          {
            customer,
            items: [{ price: this.stripe.price('PRO_MONTHLY')!, quantity: 1 }],
            trial_end: Math.floor(end.getTime() / 1000),
            trial_settings: {
              end_behavior: { missing_payment_method: 'cancel' },
            },
            payment_settings: {
              save_default_payment_method: 'on_subscription',
            },
            metadata: { tenantId, launchOffer: 'true' },
          },
          { idempotencyKey: `manar-launch-offer-${claim.id}` },
        ));
      await this.control.launchOfferClaim.update({
        where: { id: claim.id },
        data: { stripeSubscriptionId: sub.id, trialEndsAt: end },
      });
      await this.entitlements.change(
        tenantId,
        {
          plan: 'pro',
          status: 'active',
          stripeSubscriptionId: sub.id,
          billingInterval: 'month',
        },
        { type: 'system', id: 'launch-offer' },
        'launch_offer',
      );
      await this.audit.record(
        tenantId,
        AUDIT_EVENT_TYPES.LAUNCH_OFFER_CLAIMED,
        { type: 'system', id: 'launch-offer' },
        { months, subscriptionId: sub.id },
      );
      return true;
    } catch (error) {
      // Give the slot back: nobody got Pro, so nobody should hold a slot. Their next device retries.
      await this.control.launchOfferClaim
        .delete({ where: { id: claim.id } })
        .catch(() => undefined);
      this.cached = undefined;
      throw error;
    }
  }
}

export interface DeviceFacts {
  machineId: string;
  /** TPM endorsement key fingerprint, when the device attested one. */
  ekFingerprint?: string | null;
  ip?: string | null;
}
