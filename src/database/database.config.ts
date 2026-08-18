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
});

export type DatabaseConfig = z.infer<typeof DatabaseConfigSchema>;
