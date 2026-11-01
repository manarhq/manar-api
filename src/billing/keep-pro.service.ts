import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import type Stripe from 'stripe';
import { ControlPrismaService } from '../database/control-prisma.service';
import { EntitlementsService } from './entitlements.service';
import { StripeGateway } from './stripe.gateway';

const idOf = (v: string | { id: string } | null | undefined) =>
  typeof v === 'string' ? v : (v?.id ?? null);

/**
 * "Keep Pro after your free months" for the launch offer. The free subscription has no card and
 * no tax set-up, so before the first paid invoice we collect a card, a billing address and an
 * optional tax id in a Checkout session in setup mode. When it completes (webhook), the card
 * becomes the default payment method and `automatic_tax` is switched on, so UAE VAT applies from
 * the first charge. Until then nothing is charged: the trial cancels itself without a card.
 */
@Injectable()
export class KeepProService {
  private readonly logger = new Logger(KeepProService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly stripe: StripeGateway,
    private readonly entitlements: EntitlementsService,
  ) {}

  /** The open launch claim of this workspace: still on its free months and not yet kept. */
  async openClaim(tenantId: string) {
    const claim = await this.control.launchOfferClaim.findUnique({
      where: { tenantId },
    });
    return claim?.stripeSubscriptionId && !claim.keptAt ? claim : null;
  }

  async createSession(tenantId: string): Promise<{ url: string | null }> {
    const claim = await this.openClaim(tenantId);
    const ent = await this.control.tenantEntitlement.findUnique({
      where: { tenantId },
    });
    if (!claim || !ent?.stripeCustomerId)
      throw new NotFoundException({ statusCode: 404, code: 'no_launch_trial' });
    const stripe = this.stripe.client();
    const base = this.entitlements.upgradeUrl();
    const params: Stripe.Checkout.SessionCreateParams = {
      mode: 'setup',
      customer: ent.stripeCustomerId,
      // Setup mode needs a currency; the Pro price is in USD. Card only.
      currency: 'usd',
      allowed_payment_method_types: ['card'],
      billing_address_collection: 'required',
      tax_id_collection: { enabled: true },
      customer_update: { name: 'auto', address: 'auto' },
      client_reference_id: tenantId,
      metadata: {
        tenantId,
        purpose: 'keep_pro',
        subscriptionId: claim.stripeSubscriptionId!,
      },
      success_url: `${base}?keepPro=success`,
      cancel_url: `${base}?keepPro=cancelled`,
    };
    try {
      const s = await stripe.checkout.sessions.create(params);
      return { url: s.url };
    } catch (error) {
      // If this API version does not allow tax-id collection or customer updates in setup mode,
      // still collect the card and the address; `complete` copies the address from the card.
      if (
        (error as { type?: string }).type !== 'StripeInvalidRequestError' ||
        !/tax_id_collection|customer_update/.test(String(error))
      )
        throw error;
      this.logger.warn('setup-mode checkout without tax id collection');
      const rest = { ...params };
      delete rest.tax_id_collection;
      delete rest.customer_update;
      const s = await stripe.checkout.sessions.create(rest);
      return { url: s.url };
    }
  }

  /** Applies a completed setup session. Throws on any Stripe failure so the webhook is retried. */
  async complete(tenantId: string, session: Stripe.Checkout.Session) {
    if (session.mode !== 'setup' || session.metadata?.purpose !== 'keep_pro')
      return;
    const claim = await this.control.launchOfferClaim.findUnique({
      where: { tenantId },
    });
    if (
      !claim?.stripeSubscriptionId ||
      session.metadata.subscriptionId !== claim.stripeSubscriptionId
    )
      return; // not the subscription we granted: ignore
    const stripe = this.stripe.client();
    const customerId = idOf(session.customer);
    const intent = await stripe.setupIntents.retrieve(
      idOf(session.setup_intent)!,
    );
    const pmId = idOf(intent.payment_method);
    if (!customerId || !pmId || intent.status !== 'succeeded') return;

    const [pm, customer] = await Promise.all([
      stripe.paymentMethods.retrieve(pmId),
      stripe.customers.retrieve(customerId),
    ]);
    if (customer.deleted) return;
    // Tax needs an address on the customer; take the card's if Checkout did not save one.
    const a = pm.billing_details.address;
    if (!customer.address?.country && a?.country) {
      await stripe.customers.update(customerId, {
        address: {
          country: a.country,
          line1: a.line1 ?? undefined,
          line2: a.line2 ?? undefined,
          city: a.city ?? undefined,
          state: a.state ?? undefined,
          postal_code: a.postal_code ?? undefined,
        },
      });
    }
    await stripe.customers.update(customerId, {
      invoice_settings: { default_payment_method: pmId },
    });
    await stripe.subscriptions.update(claim.stripeSubscriptionId, {
      default_payment_method: pmId,
      automatic_tax: { enabled: true },
    });
    await this.control.launchOfferClaim.update({
      where: { tenantId },
      data: { keptAt: new Date() },
    });
  }
}
