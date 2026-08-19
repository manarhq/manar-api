import { z } from 'zod';

/**
 * Phase 12a (Webhooks, Section 51). See docs/security.md's webhook-signing
 * section for the full scheme this config drives:
 * `WebhookDeliveryService`/`WebhookSigner` sign every delivery with
 * `HMAC-SHA256(secret, "<timestamp>.<body>")`, sent as the
 * `Manar-Signature`/`Manar-Timestamp` headers.
 */
export const WebhooksConfigSchema = z.object({
  /**
   * How far a delivery's `Manar-Timestamp` may drift from "now" before a
   * receiver should treat the request as a replay and reject it — the
   * signing scheme's documented replay-protection window. Not enforced by
   * `manar-api` itself (it's the *sender*, never a receiver of its own
   * webhooks) — this constant exists so `docs/security.md`'s documented
   * scheme and every receiver-side verification example this repo ships
   * (see that doc) agree on one number, and so `WebhookSigner`'s own tests
   * assert against the real configured value rather than a hand-copied
   * literal.
   */
  WEBHOOK_SIGNATURE_TOLERANCE_MS: z.coerce
    .number()
    .int()
    .positive()
    .default(5 * 60 * 1000),

  /** Per-attempt HTTP timeout for a webhook delivery POST. */
  WEBHOOK_DELIVERY_TIMEOUT_MS: z.coerce
    .number()
    .int()
    .positive()
    .default(10_000),

  /** Max total delivery attempts (Temporal retry policy) before a `WebhookDelivery` is recorded as permanently `FAILED`. */
  WEBHOOK_DELIVERY_MAX_ATTEMPTS: z.coerce.number().int().positive().default(6),
});

export type WebhooksConfig = z.infer<typeof WebhooksConfigSchema>;
