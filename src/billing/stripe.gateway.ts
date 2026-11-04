import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Stripe from 'stripe';
import type { AppConfig } from '../config/env.validation';

/**
 * Price lookup keys, created by `scripts/stripe-catalog.mjs` (workspace spec 2026-11-04-payg,
 * section 4.1). No price id is configured: Checkout resolves the key, the webhook reads
 * `price.lookup_key` from the subscription items.
 */
export const PRICE = {
  PRO_MONTHLY: 'manar_pro_monthly_v2',
  PRO_YEARLY: 'manar_pro_yearly_v2',
  PRO_EXTRA_DEVICE: 'manar_pro_extra_device_v2',
  COMPANY_SEAT_MONTHLY: 'manar_company_seat_monthly_v2',
  COMPANY_SEAT_YEARLY: 'manar_company_seat_yearly_v2',
  CREDITS_1000: 'manar_credits_1000_v2',
} as const;
export type PriceKey = (typeof PRICE)[keyof typeof PRICE];

/** Billing Meters (sum aggregation over `value`, mapped by `stripe_customer_id`). */
export const METER = {
  PRO_EXTRA_DEVICES: 'manar_pro_extra_devices',
  COMPANY_SEATS: 'manar_company_seats',
} as const;
export type MeterName = (typeof METER)[keyof typeof METER];

const PRICE_TTL_MS = 10 * 60_000;

/** Business name on statements is a Dashboard setting (Fixio); nothing per-request carries it. */
@Injectable()
export class StripeGateway {
  private stripe: Stripe | null = null;
  private prices?: { at: number; ids: Map<string, string> };

  constructor(private readonly config: ConfigService<AppConfig, true>) {}

  get configured(): boolean {
    return !!this.config.get('STRIPE_SECRET_KEY', { infer: true });
  }

  /** The Stripe client; 503 when billing is not configured on this deployment. */
  client(): Stripe {
    const key = this.config.get('STRIPE_SECRET_KEY', { infer: true });
    if (!key)
      throw new ServiceUnavailableException({
        statusCode: 503,
        code: 'billing_not_configured',
      });
    this.stripe ??= new Stripe(key, { apiVersion: '2026-09-30.endive' });
    return this.stripe;
  }

  /** Throws when the signature does not match, the timestamp is stale or the secret is unset. */
  constructEvent(raw: Buffer, signature: string): Stripe.Event {
    const secret = this.config.get('STRIPE_WEBHOOK_SECRET', { infer: true });
    if (!secret) throw new Error('STRIPE_WEBHOOK_SECRET is not set');
    return this.client().webhooks.constructEvent(raw, signature, secret);
  }

  /** The active price id for a lookup key (cached 10 minutes); 503 when the catalog is missing it. */
  async price(key: PriceKey): Promise<string> {
    if (!this.prices || Date.now() - this.prices.at > PRICE_TTL_MS) {
      const ids = new Map<string, string>();
      const list = await this.client().prices.list({
        lookup_keys: Object.values(PRICE),
        active: true,
        limit: 100,
      });
      for (const p of list.data) if (p.lookup_key) ids.set(p.lookup_key, p.id);
      this.prices = { at: Date.now(), ids };
    }
    const id = this.prices.ids.get(key);
    if (!id)
      throw new ServiceUnavailableException({
        statusCode: 503,
        code: 'billing_price_missing',
        message: `Price ${key} is not in the Stripe catalog.`,
      });
    return id;
  }

  /** One meter event. The identifier makes a resend within Stripe's window a no-op. */
  async meterEvent(args: {
    meter: MeterName;
    customer: string;
    value: number;
    identifier: string;
  }): Promise<void> {
    await this.client().billing.meterEvents.create({
      event_name: args.meter,
      identifier: args.identifier,
      payload: {
        stripe_customer_id: args.customer,
        value: String(args.value),
      },
    });
  }
}
