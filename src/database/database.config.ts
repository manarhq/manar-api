import { z } from 'zod';

/**
 * Database-related environment schema, kept alongside the `database`
 * module rather than growing `AppConfigSchema` into a god-schema (see
 * `src/config/env.validation.ts`). Merged into the single root `validate()`
 * function so startup still fails fast with one itemized error list.
 */
export const DatabaseConfigSchema = z.object({
  /** Control DB connection string (Tenant/TenantDatabaseBinding/SecretReference only). */
  CONTROL_DATABASE_URL: z.string().min(1, 'CONTROL_DATABASE_URL is required'),

  /**
   * Base connection URL for tenant databases. `TenantDatabaseManager`
   * substitutes each tenant's `databaseName` into this URL's path — the
   * database named in this URL is a placeholder (e.g. Postgres's default
   * `postgres` maintenance database) and is never connected to directly
   * for tenant traffic.
   *
   * This is also the *default* env var name that `provisionTenant` records
   * in `SecretReference.reference` for the `ENV` provider — see
   * `src/database/secret-provider.ts`.
   */
  TENANT_DB_BASE_URL: z.string().min(1, 'TENANT_DB_BASE_URL is required'),

  /** Bounded LRU cache size for live tenant Prisma clients (Section 10: never unbounded). */
  TENANT_DB_CLIENT_CACHE_MAX: z.coerce.number().int().positive().default(50),

  /** Idle time (ms) after which a cached tenant client is disconnected and evicted. */
  TENANT_DB_CLIENT_IDLE_TTL_MS: z.coerce
    .number()
    .int()
    .positive()
    .default(10 * 60 * 1000),

  /**
   * How long a cached tenant client is trusted before its tenant's status is re-read from the
   * control DB (ADR-0010: a suspend in one process must reach every process). 5 s by default.
   */
  TENANT_DB_CLIENT_REVALIDATE_MS: z.coerce.number().int().min(0).default(5000),

  /**
   * Postgres connection pools. Each Nest app in a pod (human HTTP, agent mTLS) has its own control
   * pool and up to TENANT_DB_CLIENT_CACHE_MAX tenant pools, so worst case per pod is
   * 2 x (CONTROL + CACHE_MAX x TENANT) connections: size them against the server's max_connections.
   */
  DB_POOL_MAX_CONTROL: z.coerce.number().int().positive().default(10),
  DB_POOL_MAX_TENANT: z.coerce.number().int().positive().default(5),

  /**
   * How long a request waits for a free pooled connection (and for the TCP connect) before it
   * fails. An exhausted pool answers with 503 `enforcement_dependency_unavailable` after this long
   * instead of queueing without bound.
   */
  DB_POOL_CONNECT_TIMEOUT_MS: z.coerce.number().int().positive().default(3000),

  /**
   * Client-side bound on one query (all pools). Pooler-safe: it needs no startup parameter.
   * Must stay above DB_STATEMENT_TIMEOUT_MS so the server cancels the query first.
   */
  DB_QUERY_TIMEOUT_MS: z.coerce.number().int().positive().default(35_000),

  /**
   * Server-side `statement_timeout` for tenant databases (0 = off). Sent as a connection startup
   * parameter, so it is applied only to tenant clients, which connect straight to Postgres. The
   * control pool does not send it: a PgBouncer in front rejects unknown startup parameters. Set it
   * there as a role default instead (`ALTER ROLE ... SET statement_timeout`).
   */
  DB_STATEMENT_TIMEOUT_MS: z.coerce.number().int().min(0).default(30_000),
});

export type DatabaseConfig = z.infer<typeof DatabaseConfigSchema>;
