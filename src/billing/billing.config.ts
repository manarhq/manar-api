import { z } from 'zod';

const optional = z.preprocess(
  (v) => (typeof v === 'string' && v.trim() ? v.trim() : undefined),
  z.string().optional(),
);

/**
 * Stripe billing (docs/billing.md). Keys and the webhook secret are delivered by ExternalSecrets
 * (names: STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET); price ids are plain config. With no secret
 * key the Stripe endpoints answer 503 and the daily job idles; plans and limits still work.
 */
export const BillingConfigSchema = z.object({
  STRIPE_SECRET_KEY: optional,
  STRIPE_WEBHOOK_SECRET: optional,
  STRIPE_PRICE_PRO_MONTHLY: optional,
  STRIPE_PRICE_PRO_YEARLY: optional,
  STRIPE_PRICE_COMPANY_USER: optional,
  STRIPE_PRICE_EXTRA_DEVICE: optional,
  /** Console base URL for Checkout/portal return links and the upgrade link in limit errors. */
  BILLING_CONSOLE_URL: optional,
});
export type BillingConfig = z.infer<typeof BillingConfigSchema>;
