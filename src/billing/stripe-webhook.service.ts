import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import type Stripe from 'stripe';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import {
  EntitlementsService,
  type EntitlementPatch,
} from './entitlements.service';
import { COMPANY_MIN_SEATS } from './plans';
import { PRICE, StripeGateway } from './stripe.gateway';
import { WalletService } from './wallet.service';

const ACTOR = { type: 'system', id: 'stripe' } as const;
const HANDLED = new Set([
  'checkout.session.completed',
  'checkout.session.async_payment_succeeded',
  'customer.subscription.created',
  'customer.subscription.updated',
  'customer.subscription.deleted',
  'invoice.paid',
  'invoice.payment_failed',
  'charge.dispute.created',
  'charge.dispute.closed',
]);
const ENDED = new Set(['canceled', 'incomplete_expired', 'unpaid']);

const id = (v: string | { id: string } | null | undefined) =>
  typeof v === 'string' ? v : (v?.id ?? null);

/** The monthly metered item a yearly plan needs (Checkout cannot add it: mixed intervals). */
const USAGE_ITEM: Record<string, string> = {
  [PRICE.PRO_YEARLY]: PRICE.PRO_EXTRA_DEVICE,
  [PRICE.COMPANY_SEAT_YEARLY]: PRICE.COMPANY_SEAT_MONTHLY,
};

@Injectable()
export class StripeWebhookService {
  private readonly logger = new Logger(StripeWebhookService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly entitlements: EntitlementsService,
    private readonly stripe: StripeGateway,
    private readonly wallet: WalletService,
    private readonly audit: AuditService,
    private readonly tenants: TenantDatabaseManager,
  ) {}

  /** Verifies the signature on the raw body, then applies the event once. */
  async handle(raw: Buffer | undefined, signature: string | undefined) {
    let event: Stripe.Event;
    try {
      if (!raw || !signature) throw new Error('missing body or signature');
      event = this.stripe.constructEvent(raw, signature);
    } catch (error) {
      this.logger.warn(`Stripe webhook rejected: ${String(error)}`);
      throw new BadRequestException('invalid_signature');
    }
    if (!HANDLED.has(event.type)) return { received: true };

    const obj = event.data.object as unknown as {
      id: string;
      customer?: string | { id: string } | null;
      charge?: string | { id: string } | null;
      metadata?: Record<string, string> | null;
      client_reference_id?: string | null;
    };
    // A dispute names its charge, not its customer: the charge is read from Stripe.
    const customer = event.type.startsWith('charge.dispute.')
      ? id(
          (await this.stripe.client().charges.retrieve(id(obj.charge)!))
            .customer,
        )
      : id(obj.customer);
    const claimed = customer
      ? await this.control.tenantEntitlement.findUnique({
          where: { stripeCustomerId: customer },
        })
      : null;
    // The customer id we stored when we created it is the only thing that names the tenant.
    // Metadata is attacker-writable on any Stripe object; it may only agree with that.
    if (!claimed) {
      // Not a customer we created (or another product on this Stripe account): nothing to do.
      // A 4xx here would only make Stripe retry and eventually disable the endpoint.
      this.logger.warn(`Stripe event ${event.id}: unknown customer, ignored`);
      return { received: true };
    }
    const named = obj.metadata?.tenantId ?? obj.client_reference_id ?? null;
    if (named && named !== claimed.tenantId) {
      this.logger.warn(`Stripe event ${event.id}: tenant metadata mismatch`);
      throw new BadRequestException('tenant_mismatch');
    }

    // The id is recorded only after the event has been applied. apply() re-derives state from
    // Stripe and credit lots are keyed by their Stripe id, so applying twice is harmless, while
    // recording first lost the event for good if the process died between the two.
    const seen = await this.control.stripeEvent.findUnique({
      where: { id: event.id },
    });
    if (seen) return { received: true, duplicate: true };
    await this.apply(event, claimed.tenantId, claimed.stripeSubscriptionId);
    try {
      await this.control.stripeEvent.create({
        data: { id: event.id, type: event.type },
      });
    } catch (error) {
      // A concurrent delivery of the same event recorded it first; both applied the same state.
      if ((error as { code?: string }).code !== 'P2002') throw error;
    }
    return { received: true };
  }

  private async apply(
    event: Stripe.Event,
    tenantId: string,
    storedSubscription: string | null,
  ) {
    // Events can arrive in any order, so none of them is trusted for state: the subscription is
    // read live from Stripe and that state is applied. Replays and reordering converge.
    let subscriptionId: string | null = null;
    switch (event.type) {
      case 'checkout.session.completed':
      case 'checkout.session.async_payment_succeeded': {
        const session = event.data.object;
        if (session.mode === 'payment') {
          await this.creditsBought(tenantId, session);
          return;
        }
        if (session.mode !== 'subscription') return;
        subscriptionId = id(session.subscription);
        break;
      }
      case 'customer.subscription.created':
      case 'customer.subscription.updated':
      case 'customer.subscription.deleted':
        subscriptionId = event.data.object.id;
        break;
      case 'invoice.paid':
        if (event.data.object.metadata?.purpose === 'credit_top_up') {
          await this.topUpPaid(tenantId, event.data.object);
          return;
        }
        subscriptionId = storedSubscription;
        break;
      case 'charge.dispute.created':
      case 'charge.dispute.closed':
        await this.dispute(tenantId, event.data.object);
        return;
      default: // invoice.payment_failed: re-derive from the subscription we track
        subscriptionId = storedSubscription;
    }
    if (!subscriptionId) return;
    const sub = await this.stripe
      .client()
      .subscriptions.retrieve(subscriptionId);
    await this.applySubscription(tenantId, sub, storedSubscription);
  }

  /** A paid credit-pack Checkout: credits from the paid line items, never from metadata. */
  private async creditsBought(
    tenantId: string,
    session: Stripe.Checkout.Session,
  ) {
    if (session.payment_status !== 'paid') return;
    const items = await this.stripe
      .client()
      .checkout.sessions.listLineItems(session.id, { limit: 100 });
    const pack = await this.stripe.price(PRICE.CREDITS_1000);
    await this.wallet.addPaidLot(
      tenantId,
      session.id,
      'purchase',
      items.data.map((i) => ({
        lookupKey: i.price?.id === pack ? PRICE.CREDITS_1000 : null,
        quantity: i.quantity,
      })),
    );
  }

  /** An auto top-up invoice was paid. The invoice is re-read so only Stripe's own lines count. */
  private async topUpPaid(tenantId: string, invoice: Stripe.Invoice) {
    const live = await this.stripe.client().invoices.retrieve(invoice.id);
    if (live.status !== 'paid') return;
    const pack = await this.stripe.price(PRICE.CREDITS_1000);
    await this.wallet.addPaidLot(
      tenantId,
      live.id,
      'top_up',
      live.lines.data.map((l) => ({
        lookupKey:
          l.pricing?.price_details?.price === pack ? PRICE.CREDITS_1000 : null,
        quantity: l.quantity,
      })),
    );
  }

  /** A dispute freezes paid features (safety stays) until it is won; staff review it. */
  private async dispute(tenantId: string, d: Stripe.Dispute) {
    const status =
      d.status === 'won' || d.status === 'warning_closed' ? 'active' : 'frozen';
    await this.entitlements.change(tenantId, { status }, ACTOR, 'dispute');
    try {
      const client = await this.tenants.getClient(tenantId);
      await this.audit.recordSafely(client, tenantId, {
        eventType: AUDIT_EVENT_TYPES.BILLING_DISPUTE_CHANGED,
        actor: ACTOR,
        data: { disputeStatus: d.status, entitlementStatus: status },
      });
    } catch (error) {
      this.logger.error(`dispute audit failed: ${String(error)}`);
    }
  }

  private async applySubscription(
    tenantId: string,
    sub: Stripe.Subscription,
    storedSubscription: string | null,
  ) {
    const ended = ENDED.has(sub.status);
    // A late event about an old, ended subscription must not cancel the one that replaced it.
    if (ended && storedSubscription && storedSubscription !== sub.id) return;

    if (ended) {
      // Devices stay enrolled and protected; the caps now refuse new ones. trialEndsAt is kept
      // so the one free trial cannot be repeated. Credits stay until they expire.
      await this.entitlements.change(
        tenantId,
        {
          plan: 'free',
          status: 'active',
          stripeSubscriptionId: null,
          billingInterval: null,
          committedSeats: null,
        },
        ACTOR,
        'stripe',
      );
      return;
    }
    if (sub.status === 'incomplete') return;

    const keys = sub.items.data.map((i) => i.price.lookup_key);
    const yearly = sub.items.data.find(
      (i) => i.price.lookup_key! in USAGE_ITEM,
    );
    const current = await this.entitlements.get(tenantId);
    const patch: EntitlementPatch = {
      // A frozen workspace stays frozen until its dispute is won, whatever the subscription says.
      status:
        current.status === 'frozen'
          ? 'frozen'
          : sub.status === 'past_due'
            ? 'past_due'
            : 'active',
      stripeSubscriptionId: sub.id,
      billingInterval: yearly ? 'year' : 'month',
      committedSeats: null,
    };
    if (
      keys.includes(PRICE.COMPANY_SEAT_MONTHLY) ||
      keys.includes(PRICE.COMPANY_SEAT_YEARLY)
    ) {
      if (sub.status === 'trialing') {
        if (!(await this.claimCompanyTrial(tenantId, sub))) return;
        Object.assign(patch, {
          plan: 'company_trial',
          trialEndsAt: sub.trial_end ? new Date(sub.trial_end * 1000) : null,
        });
      } else {
        Object.assign(patch, { plan: 'company' });
      }
      if (yearly?.price.lookup_key === PRICE.COMPANY_SEAT_YEARLY)
        patch.committedSeats = Math.max(
          COMPANY_MIN_SEATS,
          yearly.quantity ?? COMPANY_MIN_SEATS,
        );
    } else if (
      keys.includes(PRICE.PRO_MONTHLY) ||
      keys.includes(PRICE.PRO_YEARLY)
    ) {
      Object.assign(patch, { plan: 'pro' });
    } else {
      this.logger.warn(`Subscription ${sub.id} has no known Manar price`);
      return;
    }
    await this.entitlements.change(tenantId, patch, ACTOR, 'stripe');
    if (yearly) await this.ensureUsageItem(sub, yearly.price.lookup_key!);
  }

  /** Adds the monthly metered item to a yearly subscription once (idempotent by subscription). */
  private async ensureUsageItem(sub: Stripe.Subscription, yearlyKey: string) {
    const want = USAGE_ITEM[yearlyKey]!;
    if (sub.items.data.some((i) => i.price.lookup_key === want)) return;
    await this.stripe.client().subscriptionItems.create(
      {
        subscription: sub.id,
        price: await this.stripe.price(want as never),
        proration_behavior: 'none',
      },
      { idempotencyKey: `manar-usage-item-${sub.id}` },
    );
  }

  /**
   * One company trial per workspace, person and card. A card that already started a trial
   * cancels this one at once (the workspace sees "talk to us"). Returns false when refused.
   */
  private async claimCompanyTrial(
    tenantId: string,
    sub: Stripe.Subscription,
  ): Promise<boolean> {
    const existing = await this.control.trialClaim.findFirst({
      where: { tenantId, kind: 'company' },
    });
    if (existing) return true;
    const tenant = await this.control.tenant.findUnique({
      where: { id: tenantId },
    });
    const pmId = id(sub.default_payment_method);
    const fingerprint = pmId
      ? ((await this.stripe.client().paymentMethods.retrieve(pmId)).card
          ?.fingerprint ?? null)
      : null;
    try {
      await this.control.trialClaim.create({
        data: {
          tenantId,
          kind: 'company',
          issuer: tenant?.ownerIssuer ?? `tenant:${tenantId}`,
          subject: tenant?.ownerSubject ?? tenantId,
          cardFingerprint: fingerprint,
        },
      });
      return true;
    } catch (error) {
      if ((error as { code?: string }).code !== 'P2002') throw error;
      this.logger.warn(`company trial refused for ${tenantId}: already used`);
      await this.stripe.client().subscriptions.cancel(sub.id);
      await this.entitlements.change(
        tenantId,
        {
          plan: 'free',
          status: 'active',
          stripeSubscriptionId: null,
          // Marks the trial as used, so the console offers "talk to us".
          trialEndsAt: new Date(),
        },
        ACTOR,
        'trial_refused',
      );
      return false;
    }
  }
}
