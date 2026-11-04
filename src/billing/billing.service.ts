import { randomBytes } from 'node:crypto';
import {
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import type Stripe from 'stripe';
import { ControlPrismaService } from '../database/control-prisma.service';
import { isConsumerDomain, isDisposableDomain } from '../growth/disposable';
import { BillableUsageService } from './billable-usage.service';
import { EntitlementsService } from './entitlements.service';
import { COMPANY_MIN_SEATS, TRIAL_DAYS, WALLET_PLANS } from './plans';
import { PRICE, StripeGateway, type PriceKey } from './stripe.gateway';

export const CHECKOUT_PLANS = [
  'pro_monthly',
  'pro_yearly',
  'company_monthly',
  'company_yearly',
  'company_trial',
] as const;
export type CheckoutPlan = (typeof CHECKOUT_PLANS)[number];

/** Eight random lowercase letters: Stripe's label for comparing checkout flows in the Dashboard. */
const LABEL_SUFFIX = Array.from(randomBytes(8), (b) =>
  String.fromCharCode(97 + (b % 26)),
).join('');

const subscriptionPlan = (plan: CheckoutPlan) =>
  plan.startsWith('pro') ? 'PERSONAL' : 'COMPANY';

@Injectable()
export class BillingService {
  constructor(
    private readonly control: ControlPrismaService,
    private readonly entitlements: EntitlementsService,
    private readonly usage: BillableUsageService,
    private readonly stripe: StripeGateway,
  ) {}

  async status(tenantId: string) {
    const [e, used, row, tenant] = await Promise.all([
      this.entitlements.get(tenantId),
      this.usage.usage(tenantId),
      this.control.tenantEntitlement.findUnique({ where: { tenantId } }),
      this.control.tenant.findUnique({
        where: { id: tenantId },
        select: { kind: true },
      }),
    ]);
    return {
      ...e,
      trialEndsAt: e.trialEndsAt?.toISOString() ?? null,
      committedSeats: e.committedSeats ?? null,
      usage: used,
      interval: row?.billingInterval ?? null,
      workspaceKind: tenant?.kind ?? 'PERSONAL',
      billingEnabled: this.stripe.configured,
      hasSubscription: !!row?.stripeSubscriptionId,
      // A company trial is given once per workspace, even after it ended or was cancelled.
      trialUsed: !!row?.trialEndsAt,
    };
  }

  /**
   * Stripe Checkout for a plan. Pro is for personal workspaces, Company plans for company ones.
   * Yearly plans get their monthly extras item from the webhook (Checkout cannot mix intervals).
   */
  async checkout(
    tenantId: string,
    email: string,
    plan: CheckoutPlan,
    seats?: number,
  ) {
    const [row, tenant] = await Promise.all([
      this.control.tenantEntitlement.findUnique({ where: { tenantId } }),
      this.control.tenant.findUnique({ where: { id: tenantId } }),
    ]);
    if (!tenant || tenant.kind !== subscriptionPlan(plan))
      throw new ForbiddenException({
        statusCode: 403,
        code: 'plan_not_for_workspace',
      });
    if (row?.stripeSubscriptionId)
      throw new ConflictException({
        statusCode: 409,
        code: 'already_subscribed',
        message: 'Use the billing portal to change an existing plan.',
      });
    if (plan === 'company_trial') {
      if (row?.trialEndsAt)
        throw new ConflictException({ statusCode: 409, code: 'trial_used' });
      // Company trials need a work email; free-mail and throwaway domains talk to us instead.
      const domain = email.split('@')[1]?.toLowerCase() ?? '';
      if (!domain || isConsumerDomain(domain) || isDisposableDomain(domain))
        throw new ForbiddenException({
          statusCode: 403,
          code: 'work_email_required',
        });
      const claimed = await this.control.trialClaim.findFirst({
        where: { tenantId, kind: 'company' },
      });
      if (claimed)
        throw new ConflictException({ statusCode: 409, code: 'trial_used' });
    }

    const lines: Stripe.Checkout.SessionCreateParams.LineItem[] = [];
    const add = async (key: PriceKey, quantity?: number) =>
      lines.push({
        price: await this.stripe.price(key),
        ...(quantity ? { quantity } : {}),
      });
    if (plan === 'pro_monthly') {
      await add(PRICE.PRO_MONTHLY, 1);
      await add(PRICE.PRO_EXTRA_DEVICE);
    } else if (plan === 'pro_yearly') {
      await add(PRICE.PRO_YEARLY, 1);
    } else if (plan === 'company_yearly') {
      await add(
        PRICE.COMPANY_SEAT_YEARLY,
        Math.max(COMPANY_MIN_SEATS, seats ?? COMPANY_MIN_SEATS),
      );
    } else {
      await add(PRICE.COMPANY_SEAT_MONTHLY);
    }

    const customer = await this.ensureCustomer(tenantId, email);
    await this.refuseIfSubscribed(customer);
    await this.expireOpenSessions(customer);
    const base = this.entitlements.upgradeUrl();
    const session = await this.stripe.client().checkout.sessions.create({
      mode: 'subscription',
      customer,
      line_items: lines,
      ...this.taxAndIdentity(tenantId),
      ...(plan === 'company_trial'
        ? { payment_method_collection: 'always' }
        : {}),
      subscription_data: {
        metadata: { tenantId },
        // A yearly price and a monthly metered item on one subscription.
        billing_mode: { type: 'flexible' },
        ...(plan === 'company_trial'
          ? {
              trial_period_days: TRIAL_DAYS,
              trial_settings: {
                end_behavior: { missing_payment_method: 'cancel' },
              },
            }
          : {}),
      },
      success_url: `${base}?checkout=success`,
      cancel_url: `${base}?checkout=cancelled`,
      integration_identifier: `manar_billing_${LABEL_SUFFIX}`,
    });
    return { url: session.url };
  }

  /** Credit packs ($5 = 1,000 credits), one-time Checkout with a tax invoice. Paid plans only. */
  async buyCredits(tenantId: string, packs: number) {
    const e = await this.entitlements.get(tenantId);
    const row = await this.control.tenantEntitlement.findUnique({
      where: { tenantId },
    });
    if (!WALLET_PLANS.has(e.plan) || !row?.stripeCustomerId)
      throw new ForbiddenException({
        statusCode: 403,
        code: 'paid_plan_required',
      });
    if (e.status === 'frozen')
      throw new ForbiddenException({
        statusCode: 403,
        code: 'paid_features_paused',
      });
    await this.expireOpenSessions(row.stripeCustomerId);
    const base = this.entitlements.upgradeUrl();
    const session = await this.stripe.client().checkout.sessions.create({
      mode: 'payment',
      customer: row.stripeCustomerId,
      line_items: [
        {
          price: await this.stripe.price(PRICE.CREDITS_1000),
          quantity: packs,
          adjustable_quantity: { enabled: true, minimum: 1, maximum: 20 },
        },
      ],
      ...this.taxAndIdentity(tenantId),
      invoice_creation: {
        enabled: true,
        invoice_data: { metadata: { tenantId, purpose: 'credits' } },
      },
      success_url: `${base}?credits=success`,
      cancel_url: `${base}?credits=cancelled`,
      integration_identifier: `manar_credits_${LABEL_SUFFIX}`,
    });
    return { url: session.url };
  }

  private taxAndIdentity(tenantId: string) {
    return {
      automatic_tax: { enabled: true },
      tax_id_collection: { enabled: true },
      billing_address_collection: 'required' as const,
      // Needed so Stripe may save the tax id and address entered at checkout on the Customer.
      customer_update: { name: 'auto' as const, address: 'auto' as const },
      client_reference_id: tenantId,
      metadata: { tenantId },
    };
  }

  /** Only one checkout can be live: expire any the customer left open in another tab. */
  private async expireOpenSessions(customer: string) {
    const stripe = this.stripe.client();
    for await (const open of stripe.checkout.sessions.list({
      customer,
      status: 'open',
    }))
      await stripe.checkout.sessions.expire(open.id);
  }

  /** 409 when the customer already has a live subscription in Stripe, even one our row has not seen yet. */
  private async refuseIfSubscribed(customer: string) {
    const subs = await this.stripe
      .client()
      .subscriptions.list({ customer, status: 'all', limit: 100 });
    if (
      subs.data.some((s) =>
        ['active', 'trialing', 'past_due', 'incomplete'].includes(s.status),
      )
    )
      throw new ConflictException({
        statusCode: 409,
        code: 'already_subscribed',
        message: 'Use the billing portal to change an existing plan.',
      });
  }

  async portal(tenantId: string) {
    const row = await this.control.tenantEntitlement.findUnique({
      where: { tenantId },
    });
    if (!row?.stripeCustomerId)
      throw new NotFoundException({
        statusCode: 404,
        code: 'no_billing_account',
      });
    const session = await this.stripe.client().billingPortal.sessions.create({
      customer: row.stripeCustomerId,
      return_url: this.entitlements.upgradeUrl(),
    });
    return { url: session.url };
  }

  /** One Stripe customer per tenant; the id is stored before checkout so webhooks resolve the tenant from it. */
  async ensureCustomer(tenantId: string, email?: string) {
    const row = await this.control.tenantEntitlement.findUnique({
      where: { tenantId },
    });
    if (row?.stripeCustomerId) return row.stripeCustomerId;
    const tenant = await this.control.tenant.findUnique({
      where: { id: tenantId },
      select: { name: true },
    });
    const customer = await this.stripe
      .client()
      .customers.create(
        { name: tenant?.name, email, metadata: { tenantId } },
        { idempotencyKey: `manar-customer-${tenantId}` },
      );
    await this.entitlements.change(
      tenantId,
      { stripeCustomerId: customer.id },
      { type: 'system', id: 'billing' },
      'customer',
    );
    return customer.id;
  }
}
