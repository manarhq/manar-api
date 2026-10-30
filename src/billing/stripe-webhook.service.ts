import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import type Stripe from 'stripe';
import { ControlPrismaService } from '../database/control-prisma.service';
import {
  EntitlementsService,
  type EntitlementPatch,
} from './entitlements.service';
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
    const named = obj.metadata?.tenantId ?? obj.client_reference_id ?? null;
    if (named && named !== claimed?.tenantId) {
      this.logger.warn(`Stripe event ${event.id}: tenant metadata mismatch`);
      throw new BadRequestException('tenant_mismatch');
    }
    if (!claimed) return { received: true };

    try {
      await this.control.stripeEvent.create({
        data: { id: event.id, type: event.type },
      });
    } catch (error) {
      if ((error as { code?: string }).code === 'P2002')
        return { received: true, duplicate: true };
      throw error;
    }
    try {
      await this.apply(event, claimed.tenantId, claimed.stripeSubscriptionId);
    } catch (error) {
      // Free the id so Stripe's retry is applied rather than skipped as a duplicate.
      await this.control.stripeEvent
        .delete({ where: { id: event.id } })
        .catch(() => undefined);
      throw error;
    }
    return { received: true };
  }

  private async apply(
    event: Stripe.Event,
    tenantId: string,
    storedSubscription: string | null,
  ) {
    const at = new Date(event.created * 1000);
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const subscriptionId = id(session.subscription);
        if (session.mode !== 'subscription' || !subscriptionId) return;
        const sub = await this.stripe
          .client()
          .subscriptions.retrieve(subscriptionId);
        return this.applySubscription(
          tenantId,
          sub,
          at,
          false,
          storedSubscription,
        );
      }
      case 'customer.subscription.created':
      case 'customer.subscription.updated':
      case 'customer.subscription.deleted':
        return this.applySubscription(
          tenantId,
          event.data.object,
          at,
          event.type.endsWith('deleted'),
          storedSubscription,
        );
      case 'invoice.paid':
        return this.setStatus(tenantId, 'active', at);
      case 'invoice.payment_failed':
        return this.setStatus(tenantId, 'past_due', at);
    }
  }

  private async setStatus(
    tenantId: string,
    status: 'active' | 'past_due',
    at: Date,
  ) {
    const e = await this.entitlements.get(tenantId);
    if (e.plan !== 'pro' && e.plan !== 'company') return;
    await this.entitlements.change(
      tenantId,
      { status, lastStripeEventAt: at },
      ACTOR,
      'stripe',
    );
  }

  private async applySubscription(
    tenantId: string,
    sub: Stripe.Subscription,
    at: Date,
    deleted: boolean,
    storedSubscription: string | null,
  ) {
    const row = await this.control.tenantEntitlement.findUnique({
      where: { tenantId },
    });
    if (row?.lastStripeEventAt && at < row.lastStripeEventAt) return; // stale, out of order
    // A late "deleted" for an old subscription must not cancel the one that replaced it.
    if (
      (deleted || ENDED.has(sub.status)) &&
      storedSubscription &&
      storedSubscription !== sub.id
    )
      return;

    if (deleted || ENDED.has(sub.status)) {
      // Devices stay enrolled and protected; the caps in assertWithin now refuse new ones.
      await this.entitlements.change(
        tenantId,
        {
          plan: 'free',
          status: 'active',
          stripeSubscriptionId: null,
          billingInterval: null,
          trialEndsAt: null,
          lastStripeEventAt: at,
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
      lastStripeEventAt: at,
    };
    if (prices.includes(this.stripe.price('COMPANY_USER') ?? '-')) {
      Object.assign(patch, {
        plan: 'company',
        billingInterval: null,
        trialEndsAt: null,
      });
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
