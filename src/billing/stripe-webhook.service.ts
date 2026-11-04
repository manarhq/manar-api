import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import type Stripe from 'stripe';
import { ControlPrismaService } from '../database/control-prisma.service';
import {
  EntitlementsService,
  type EntitlementPatch,
} from './entitlements.service';
import { KeepProService } from './keep-pro.service';
import { StripeGateway } from './stripe.gateway';

const ACTOR = { type: 'system', id: 'stripe' } as const;
const HANDLED = new Set([
  'checkout.session.completed',
  'customer.subscription.created',
  'customer.subscription.updated',
  'customer.subscription.deleted',
  'invoice.paid',
  'invoice.payment_failed',
]);
const ENDED = new Set(['canceled', 'incomplete_expired', 'unpaid']);

const id = (v: string | { id: string } | null | undefined) =>
  typeof v === 'string' ? v : (v?.id ?? null);

@Injectable()
export class StripeWebhookService {
  private readonly logger = new Logger(StripeWebhookService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly entitlements: EntitlementsService,
    private readonly stripe: StripeGateway,
    private readonly keepPro?: KeepProService,
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
      metadata?: Record<string, string> | null;
      client_reference_id?: string | null;
    };
    const customer = id(obj.customer);
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
    // Stripe, so applying twice is harmless, while recording first lost the payment for good if
    // the process died (rollout, OOM) or the clean-up failed between the two: Stripe's retry was
    // then answered "duplicate" and the plan never changed.
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
      case 'checkout.session.completed': {
        const session = event.data.object;
        if (session.mode === 'setup') {
          // Launch offer: card, address and tax id collected; turn automatic tax on.
          await this.keepPro?.complete(tenantId, session);
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
      default: // invoice.paid, invoice.payment_failed: re-derive from the subscription we track
        subscriptionId = storedSubscription;
    }
    if (!subscriptionId) return;
    const sub = await this.stripe
      .client()
      .subscriptions.retrieve(subscriptionId);
    await this.applySubscription(tenantId, sub, storedSubscription);
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
      // so the one free trial cannot be repeated.
      await this.entitlements.change(
        tenantId,
        {
          plan: 'free',
          status: 'active',
          stripeSubscriptionId: null,
          billingInterval: null,
        },
        ACTOR,
        'stripe',
      );
      return;
    }
    if (sub.status === 'incomplete') return;

    const prices = sub.items.data.map((i) => i.price.id);
    const patch: EntitlementPatch = {
      status: sub.status === 'past_due' ? 'past_due' : 'active',
      stripeSubscriptionId: sub.id,
    };
    if (prices.includes(this.stripe.price('COMPANY_USER') ?? '-')) {
      Object.assign(patch, { plan: 'company', billingInterval: null });
    } else if (prices.includes(this.stripe.price('PRO_MONTHLY') ?? '-')) {
      Object.assign(patch, { plan: 'pro', billingInterval: 'month' });
    } else if (prices.includes(this.stripe.price('PRO_YEARLY') ?? '-')) {
      Object.assign(patch, { plan: 'pro', billingInterval: 'year' });
    } else {
      this.logger.warn(`Subscription ${sub.id} has no known Manar price`);
      return;
    }
    await this.entitlements.change(tenantId, patch, ACTOR, 'stripe');
  }
}
