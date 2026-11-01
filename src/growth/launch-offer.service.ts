import { createHash } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { BillingService } from '../billing/billing.service';
import { EntitlementsService } from '../billing/entitlements.service';
import { StripeGateway } from '../billing/stripe.gateway';
import type { AppConfig } from '../config/env.validation';
import { ControlPrismaService } from '../database/control-prisma.service';
import { GrowthAuditService } from './growth-audit.service';
import { growthSetting } from './growth.config';

export interface LaunchOfferCounter {
  enabled: boolean;
  total: number;
  claimed: number;
  remaining: number;
}

const COUNTER_TTL_MS = 15_000;
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
    machineId: string,
  ): Promise<boolean> {
    try {
      return await this.claim(tenantId, machineId);
    } catch (error) {
      this.logger.error(
        `launch offer failed for ${tenantId}: ${String(error)}`,
      );
      return false;
    }
  }

  async claim(tenantId: string, machineId: string): Promise<boolean> {
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

    const slots = growthSetting(this.config, 'LAUNCH_OFFER_SLOTS');
    const device = deviceHash(machineId);
    const issuer = tenant.ownerIssuer;
    const subject = tenant.ownerSubject;
    const claim = await this.control.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext('launch-offer'))`;
      const taken = await tx.launchOfferClaim.findFirst({
        where: {
          OR: [{ issuer, subject }, { deviceHash: device }, { tenantId }],
        },
      });
      if (taken) return null;
      if ((await tx.launchOfferClaim.count()) >= slots) return null;
      return tx.launchOfferClaim.create({
        data: { issuer, subject, tenantId, deviceHash: device },
      });
    });
    if (!claim) return false;
    this.cached = undefined;

    try {
      const owner = await this.control.membership.findUnique({
        where: { issuer_subject_tenantId: { issuer, subject, tenantId } },
        select: { email: true },
      });
      if (!owner?.email)
        throw new Error('owner has no email for the Stripe customer');
      const months = growthSetting(this.config, 'LAUNCH_OFFER_MONTHS');
      const customer = await this.billing.ensureCustomer(tenantId, owner.email);
      const end = new Date();
      end.setUTCMonth(end.getUTCMonth() + months);
      const sub = await this.stripe.client().subscriptions.create(
        {
          customer,
          items: [{ price: this.stripe.price('PRO_MONTHLY')!, quantity: 1 }],
          trial_end: Math.floor(end.getTime() / 1000),
          trial_settings: {
            end_behavior: { missing_payment_method: 'cancel' },
          },
          payment_settings: { save_default_payment_method: 'on_subscription' },
          metadata: { tenantId, launchOffer: 'true' },
        },
        { idempotencyKey: `manar-launch-offer-${tenantId}` },
      );
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
