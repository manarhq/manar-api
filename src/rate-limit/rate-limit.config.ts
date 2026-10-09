import { z } from 'zod';

/**
 * Phase 12a (Redis-backed rate limiting, decision #76). Two independently
 * configured surfaces, deliberately not one shared limit:
 *
 *   - The human-facing JWT surface (`AppModule`), scoped **per-tenant**
 *     (`TenantThrottlerGuard`) -- a burst from one tenant's dashboard users
 *     must never exhaust the limit shared by every other tenant.
 *   - The mTLS agent-facing `/agent/v1/*` surface (`AgentMtlsAppModule`),
 *     scoped **per-agent** (`AgentThrottlerGuard`) -- one misbehaving agent
 *     must never exhaust a limit shared with every other agent in its own
 *     tenant, let alone every agent across every tenant.
 *
 * Defaults are generous enough not to interfere with normal use (a human
 * dashboard polling a few endpoints, an agent working through a task) while
 * still bounding a genuine burst -- see docs/security.md's rate-limiting
 * section for the reasoning.
 */
export const RateLimitConfigSchema = z.object({
  /** Window length for the human JWT surface. */
  RATE_LIMIT_HUMAN_TTL_MS: z.coerce.number().int().positive().default(60_000),
  /** Max requests per tenant per `RATE_LIMIT_HUMAN_TTL_MS` window. */
  RATE_LIMIT_HUMAN_LIMIT: z.coerce.number().int().positive().default(300),
  /** Window length for the mTLS `/agent/v1/*` surface. */
  RATE_LIMIT_AGENT_TTL_MS: z.coerce.number().int().positive().default(60_000),
  /** Max requests per agent per `RATE_LIMIT_AGENT_TTL_MS` window. */
  RATE_LIMIT_AGENT_LIMIT: z.coerce.number().int().positive().default(120),
});

export type RateLimitConfig = z.infer<typeof RateLimitConfigSchema>;
