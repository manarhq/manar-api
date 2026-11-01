import { randomBytes } from 'node:crypto';
import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { ControlPrismaService } from '../database/control-prisma.service';
import { BillableUsageService } from './billable-usage.service';
import { EntitlementsService } from './entitlements.service';
import { StripeGateway } from './stripe.gateway';

export type CheckoutPlan = 'pro_monthly' | 'pro_yearly' | 'company';

/** Eight random lowercase letters: Stripe's label for comparing checkout flows in the Dashboard. */
const LABEL_SUFFIX = Array.from(randomBytes(8), (b) =>
  String.fromCharCode(97 + (b % 26)),
).join('');

@Injectable()
export class BillingService {
  constructor(
    private readonly control: ControlPrismaService,
    private readonly entitlements: EntitlementsService,
    private readonly usage: BillableUsageService,
    private readonly stripe: StripeGateway,
  ) {}

  async status(tenantId: string) {
    const [e, used, row] = await Promise.all([
      this.entitlements.get(tenantId),
      this.usage.usage(tenantId),
      this.control.tenantEntitlement.findUnique({ where: { tenantId } }),
    ]);
    return {
      ...e,
      trialEndsAt: e.trialEndsAt?.toISOString() ?? null,
      usage: used,
      interval: row?.billingInterval ?? null,
      billingEnabled: this.stripe.configured,
      hasSubscription: !!row?.stripeSubscriptionId,
      keepPro: await this.keepProOffer(tenantId),
    };
  }

  /** Launch offer: free months still running and no card yet, so the console shows "Keep Pro". */
  private async keepProOffer(tenantId: string) {
    const claim = await this.control.launchOfferClaim.findUnique({
      where: { tenantId },
    });
    return claim?.stripeSubscriptionId &&
      !claim.keptAt &&
      claim.trialEndsAt &&
      claim.trialEndsAt > new Date()
      ? { trialEndsAt: claim.trialEndsAt.toISOString() }
      : null;
  }

  async checkout(tenantId: string, email: string, plan: CheckoutPlan) {
    const row = await this.control.tenantEntitlement.findUnique({
      where: { tenantId },
    });
    if (row?.stripeSubscriptionId)
      throw new ConflictException({
        statusCode: 409,
        code: 'already_subscribed',
        message: 'Use the billing portal to change an existing plan.',
      });
    const stripe = this.stripe.client();
    const lines: { price: string; quantity: number }[] = [];
    if (plan === 'company') {
      const price = this.stripe.price('COMPANY_USER');
      if (!price)
        throw new NotFoundException('company price is not configured');
      const { users } = await this.usage.billable(tenantId);
      lines.push({ price, quantity: Math.max(1, users) });
    } else {
      const price = this.stripe.price(
        plan === 'pro_yearly' ? 'PRO_YEARLY' : 'PRO_MONTHLY',
      );
      if (!price) throw new NotFoundException('pro price is not configured');
      lines.push({ price, quantity: 1 });
    }
    const customer = await this.ensureCustomer(tenantId, email);
    await this.refuseIfSubscribed(customer);
    // Only one checkout can be live: expire any the customer left open in another tab.
    for await (const open of stripe.checkout.sessions.list({
      customer,
      status: 'open',
    }))
      await stripe.checkout.sessions.expire(open.id);
    const base = this.entitlements.upgradeUrl();
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer,
      line_items: lines,
      automatic_tax: { enabled: true },
      tax_id_collection: { enabled: true },
      billing_address_collection: 'required',
      // Needed so Stripe may save the tax id and address entered at checkout on the Customer.
      customer_update: { name: 'auto', address: 'auto' },
      client_reference_id: tenantId,
      metadata: { tenantId },
      subscription_data: { metadata: { tenantId } },
      success_url: `${base}?checkout=success`,
      cancel_url: `${base}?checkout=cancelled`,
      integration_identifier: `manar_billing_${LABEL_SUFFIX}`,
    });
    return { url: session.url };
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
