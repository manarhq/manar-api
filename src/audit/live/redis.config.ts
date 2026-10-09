import { accessSync, constants, readFileSync } from 'node:fs';
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

/** A CA file that is set must be readable now, so a bad mount stops startup. */
export function unreadableFile(path: string | undefined): boolean {
  if (!path) return false;
  try {
    accessSync(path, constants.R_OK);
    return false;
  } catch {
    return true;
  }
}

function urlCredentials(raw: string): boolean {
  try {
    const u = new URL(raw);
    return Boolean(u.username || u.password);
  } catch {
    return false;
  }
}

/**
 * Cross-field rules for the Redis connection, checked at startup (`AppConfigSchema`) and again
 * by `redisClientOptions`. Credentials only travel over TLS: an ACL user or password, in the
 * URL or in `REDIS_USERNAME`/`REDIS_PASSWORD`, needs `rediss://`.
 */
export function redisConfigIssues(c: Partial<RedisConfig>): string[] {
  const url = c.REDIS_URL ?? '';
  const tls = url.startsWith('rediss://');
  const issues: string[] = [];
  if (c.REDIS_TLS_CA_FILE && !tls)
    issues.push('REDIS_TLS_CA_FILE is set but REDIS_URL is not rediss://');
  if (unreadableFile(c.REDIS_TLS_CA_FILE))
    issues.push('REDIS_TLS_CA_FILE cannot be read');
  if (c.REDIS_USERNAME && !c.REDIS_PASSWORD)
    issues.push('REDIS_USERNAME is set without REDIS_PASSWORD');
  if ((c.REDIS_PASSWORD || urlCredentials(url)) && !tls)
    issues.push(
      'Redis credentials need a rediss:// REDIS_URL (they would be sent in clear)',
    );
  return issues;
}

/**
 * Options for every node-redis client in this process. TLS is on when `REDIS_URL` is
 * `rediss://`. A misconfigured connection throws rather than connecting in plaintext.
 */
export function redisClientOptions(
  get: <K extends keyof RedisConfig>(key: K) => RedisConfig[K],
  socket: Record<string, unknown> = {},
) {
  const c: Partial<RedisConfig> = {
    REDIS_URL: get('REDIS_URL'),
    REDIS_USERNAME: get('REDIS_USERNAME'),
    REDIS_PASSWORD: get('REDIS_PASSWORD'),
    REDIS_TLS_CA_FILE: get('REDIS_TLS_CA_FILE'),
  };
  const [issue] = redisConfigIssues(c);
  if (issue) throw new Error(issue);
  const {
    REDIS_URL: url,
    REDIS_USERNAME: username,
    REDIS_PASSWORD: password,
  } = c;
  const caFile = c.REDIS_TLS_CA_FILE;
  return {
    url: url as string,
    ...(username ? { username } : {}),
    ...(password ? { password } : {}),
    socket: {
      ...socket,
      ...(caFile ? { tls: true as const, ca: readFileSync(caFile) } : {}),
    },
  };
}
