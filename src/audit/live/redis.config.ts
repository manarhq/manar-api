import { readFileSync } from 'node:fs';
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
  /** ACL user and password (Valkey/Redis `AUTH`). Credentials in `REDIS_URL` take precedence. */
  REDIS_USERNAME: z.string().min(1).optional(),
  REDIS_PASSWORD: z.string().min(1).optional(),
  /** PEM CA bundle for a `rediss://` URL whose server certificate is not from a public CA. */
  REDIS_TLS_CA_FILE: z.string().min(1).optional(),
});

export type RedisConfig = z.infer<typeof RedisConfigSchema>;

/**
 * Options for every node-redis client in this process. TLS is on when `REDIS_URL` is
 * `rediss://`; a CA file without TLS is a misconfiguration and throws rather than silently
 * connecting in plaintext.
 */
export function redisClientOptions(
  get: <K extends keyof RedisConfig>(key: K) => RedisConfig[K],
  socket: Record<string, unknown> = {},
) {
  const url = get('REDIS_URL');
  const caFile = get('REDIS_TLS_CA_FILE');
  if (caFile && !url.startsWith('rediss://'))
    throw new Error('REDIS_TLS_CA_FILE is set but REDIS_URL is not rediss://');
  const username = get('REDIS_USERNAME');
  const password = get('REDIS_PASSWORD');
  return {
    url,
    ...(username ? { username } : {}),
    ...(password ? { password } : {}),
    socket: {
      ...socket,
      ...(caFile ? { tls: true as const, ca: readFileSync(caFile) } : {}),
    },
  };
}
