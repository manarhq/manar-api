import { z } from 'zod';

/**
 * Phase 12a (Section 8, `Idempotency-Key` support). How long a claimed key
 * (and, once the original request completes, its cached response) stays
 * valid — a replay with the same key inside this window returns the
 * original response without re-executing the handler; a replay after this
 * window elapses is treated as a brand new request. 24 hours is generous
 * enough to cover any realistic client retry/backoff sequence for the
 * mutation endpoints this applies to (agent creation, policy publish,
 * kill-switch activation, webhook registration — see
 * `docs/security.md`'s idempotency section for the full list and why each
 * one qualifies).
 */
export const IdempotencyConfigSchema = z.object({
  IDEMPOTENCY_KEY_TTL_MS: z.coerce
    .number()
    .int()
    .positive()
    .default(24 * 60 * 60 * 1000),
});

export type IdempotencyConfig = z.infer<typeof IdempotencyConfigSchema>;
