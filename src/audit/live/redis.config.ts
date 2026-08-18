import { z } from 'zod';

/**
 * Phase 9b (Live SSE, Section 62) — connection settings for
 * `RedisPubSubService`. Read by both the publishing side
 * (`AuditIndexerService`, which publishes every consumed Kafka envelope to
 * its tenant's channel — see `docs/audit-chain.md`) and the subscribing
 * side (`LiveEventsController`'s `GET /events/live`).
 */
export const RedisConfigSchema = z.object({
  /** Matches `deploy/docker-compose.yml`'s `redis` service's default host-mapped port. */
  REDIS_URL: z.string().min(1).default('redis://localhost:6379'),
});

export type RedisConfig = z.infer<typeof RedisConfigSchema>;
