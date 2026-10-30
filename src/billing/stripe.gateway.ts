import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Stripe from 'stripe';
import type { AppConfig } from '../config/env.validation';

/** Business name on statements is a Dashboard setting (Fixio); nothing per-request carries it. */
@Injectable()
export class StripeGateway {
  private stripe: Stripe | null = null;

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

  price(name: 'PRO_MONTHLY' | 'PRO_YEARLY' | 'COMPANY_USER' | 'EXTRA_DEVICE') {
    return this.config.get(`STRIPE_PRICE_${name}`, { infer: true });
  }
}
