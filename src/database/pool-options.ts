import type { PrismaPg } from '@prisma/adapter-pg';

/** The adapter's own pool config type (two `@types/pg` versions are installed). */
type PoolConfig = Exclude<
  ConstructorParameters<typeof PrismaPg>[0],
  string | { connect: unknown }
>;

export interface PoolSettings {
  max: number;
  connectTimeoutMs: number;
  queryTimeoutMs: number;
  /** Server-side statement_timeout; 0 or undefined sends nothing. */
  statementTimeoutMs?: number;
}

/**
 * `pg` pool options for a Prisma `PrismaPg` adapter. Bounded size, a bounded wait for a free
 * connection (`connectionTimeoutMillis` also bounds the TCP connect) and a bounded query.
 */
export function pgPoolOptions(
  connectionString: string,
  s: PoolSettings,
): PoolConfig {
  return {
    connectionString,
    max: s.max,
    connectionTimeoutMillis: s.connectTimeoutMs,
    query_timeout: s.queryTimeoutMs,
    ...(s.statementTimeoutMs
      ? { statement_timeout: s.statementTimeoutMs }
      : {}),
  };
}

type Get = (key: string) => unknown;

const num = (v: unknown, fallback: number): number =>
  typeof v === 'number' && Number.isFinite(v) ? v : fallback;

/**
 * Pool settings from the validated config (defaults mirror `DatabaseConfigSchema`, for callers
 * whose config object is a partial test double).
 */
export function poolSettings(
  get: Get,
  kind: 'control' | 'tenant',
): PoolSettings {
  return {
    max:
      kind === 'control'
        ? num(get('DB_POOL_MAX_CONTROL'), 5)
        : num(get('DB_POOL_MAX_TENANT'), 3),
    connectTimeoutMs: num(get('DB_POOL_CONNECT_TIMEOUT_MS'), 3000),
    queryTimeoutMs: num(get('DB_QUERY_TIMEOUT_MS'), 35_000),
    // The control pool sends NO startup parameters: in production it reaches the control DB
    // through PgBouncer, which rejects an unknown startup parameter (08P01) for every
    // connection. Its server-side statement_timeout is set on the role instead
    // (ALTER ROLE ... IN DATABASE manar_control SET statement_timeout), and the client
    // query_timeout above still bounds each query. Tenant pools connect directly.
    statementTimeoutMs:
      kind === 'tenant'
        ? num(get('DB_STATEMENT_TIMEOUT_MS'), 30_000)
        : undefined,
  };
}
