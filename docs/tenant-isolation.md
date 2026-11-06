# Tenant isolation

This is `manar-api`'s implementation of the control-plane/tenant database
split from Section 10 of the master prompt (Phase 2:
`docs/superpowers/specs/2026-08-18-phase2-persistence-tenancy-design.md`).
Phase 3 (Human Authentication, `docs/human-auth.md`) builds directly on top
of this split — a tenant's Keycloak realm is provisioned alongside its
database, and its issuer URL is the allow-list key `JwtAuthGuard` resolves
a request's tenant identity from.

## The split

There are two independent Prisma schemas, each generating its own distinct
typed client:

| Schema  | File                    | Generated client               | Holds                                                                                                           |
| ------- | ----------------------- | ------------------------------ | --------------------------------------------------------------------------------------------------------------- |
| Control | `prisma/control.prisma` | `src/generated/control-client` | `Tenant`, `TenantDatabaseBinding`, `SecretReference` — provisioning/routing metadata only                       |
| Tenant  | `prisma/tenant.prisma`  | `src/generated/tenant-client`  | One fully isolated Postgres **database per tenant**, empty schema this phase — domain models arrive in Phase 3+ |

No business or security data (agents, tasks, policies, audit records, ...)
is ever stored in the control DB — enforced by code review, not by a
runtime check, since Prisma schemas are compile-time-fixed and a reviewer
can see at a glance whether a model belongs in `control.prisma`.

For local dev (`deploy/docker-compose.yml`), the control database and every
tenant database are separate _databases_ on one Postgres server — isolation
is enforced by Postgres's database boundary, not by server separation.
There is no SQL surface for cross-database queries without `dblink`/FDW,
which this project never uses. Production may later split tenant databases
across separate server instances without any application-level contract
change: `TenantDatabaseManager` resolves a connection string per tenant: it
never assumes tenants share a server.

## Why isolation is structural, not a `WHERE tenantId = ...` filter

Every tenant gets its own physical database, not a shared schema with a
tenant-scoping column. This means a bug that forgets a `WHERE` clause, an
ORM query built without a tenant filter, or a raw SQL injection can only
ever touch _that one tenant's_ database — there is no shared table for a
missing filter to leak across. The isolation boundary is Postgres's
database boundary itself, which every code path is forced through: there is
no client that can see two tenants' data at once, because
`TenantDatabaseManager.getClient(tenantId)` hands back a Prisma client
already bound to exactly one tenant's connection string, and nothing in the
codebase constructs a tenant Prisma client any other way.

The five tests in `src/database/tenant-database-manager.spec.ts` exist to
prove this structurally (real Postgres, not mocked) rather than merely
asserting that application code remembers to add a filter:

1. Two provisioned tenants get distinct `databaseName`s and distinct
   `SecretReference`s.
2. Each tenant's Prisma client's `SELECT current_database()` returns that
   tenant's own database — never the other's.
3. `TenantDatabaseManager` never returns the same live client instance for
   two different tenants, and its bounded LRU cache evicts under load.
4. An unknown or deprovisioned tenant ID fails closed (throws) — never
   falls back to the control DB or another tenant.
5. Re-provisioning an existing slug fails with a clear conflict error
   rather than silently creating a duplicate database.

## `SecretProvider`: the swap point

```ts
interface SecretReferenceDescriptor {
  provider: 'ENV' | 'OPENBAO';
  reference: string;
}
interface SecretProvider {
  resolve(ref: SecretReferenceDescriptor): Promise<string>;
}
```

`SecretReference.provider`/`SecretReference.reference` (control DB) name
_how_ to fetch a tenant's database credential, without the rest of the
codebase caring how that lookup actually happens. This phase ships exactly
one implementation, `EnvSecretProvider`
(`src/database/env-secret-provider.ts`): it reads a base Postgres
connection URL from the environment variable named by `reference` (by
convention, `TENANT_DB_BASE_URL` —
`DEFAULT_TENANT_DB_SECRET_REFERENCE` in `src/database/secret-provider.ts`).
`TenantDatabaseManager` then substitutes the tenant's `databaseName` into
that URL's path to get the tenant-specific connection string.

Phase 4/17 adds `OpenBaoSecretProvider`, implementing the same interface
against a real secret store instead of an env var. No caller of
`SecretProvider` changes when that lands — `TenantDatabaseManager`,
`provisionTenant`, and the CLI never know or care which implementation is
wired up; only `src/database/database.module.ts`'s provider binding
changes.

Reading `process.env` directly inside `EnvSecretProvider` is a deliberate,
documented exception to "only the config module reads `process.env`"
(`src/config/config.module.ts`): the variable _name_ is data
(`SecretReference.reference`, an opaque string chosen at provisioning time),
not a fixed key `AppConfigSchema` can declare ahead of time. `OpenBaoSecretProvider`
will face the exact same shape of problem against a real secret store — this
is exactly why the lookup lives behind an interface instead of being
inlined into `TenantDatabaseManager`.

## `TenantDatabaseManager`

- **`resolveTenant(tenantId)`** — loads `Tenant` + `TenantDatabaseBinding`
  (+ its `SecretReference`) from the control DB. Existence-only check;
  throws `TenantNotFoundError` if either doesn't exist.
- **`getClient(tenantId)`** — returns a cached tenant-scoped Prisma client,
  or creates one. Backed by a bounded LRU cache
  (`TENANT_DB_CLIENT_CACHE_MAX`, default 50) with idle eviction
  (`TENANT_DB_CLIENT_IDLE_TTL_MS`, default 10 minutes) — never an unbounded
  per-request client. Fails closed (throws `TenantNotFoundError`) for any
  tenant that isn't `ACTIVE` with an `ACTIVE` database binding, which
  covers unknown IDs and deprovisioned/deleted/suspended tenants alike.
- **`provisionTenant({ slug, name, residency, ... })`** — creates the
  `Tenant`/`TenantDatabaseBinding`/`SecretReference` rows, issues
  `CREATE DATABASE` against the Postgres server via a raw `pg` admin
  connection (Prisma doesn't run well as the driver for DDL like `CREATE
DATABASE`, which can't run inside a transaction block), then spawns
  `prisma migrate deploy` for `tenant.prisma` as a child process with
  `DATABASE_URL` set to the new tenant's resolved connection string.
  Updates `provisioningStatus`/`lastMigratedAt`/`lastMigrationVersion` on
  success. **On failure after the control-DB rows exist** (e.g. the
  migration fails), the tenant is left in `PROVISIONING` status for manual
  inspection — this phase does not implement automatic rollback; see "Known
  limitations" below.
- **`deprovisionTenant(tenantId)`** — transitions the tenant to `DELETED`
  and evicts any cached client. Does **not** drop the database.
- **`dangerouslyDropTenantDatabase(tenantId)`** — the explicit, separately
  named destructive operation that _does_ drop a tenant's database.
  Deliberately not called by `deprovisionTenant`, the CLI, or any other
  command path — consistent with this project's stance against silent
  destructive defaults. Requires the tenant to already be `DELETED` as a
  minimal safety check. A future admin-tooling phase decides how (and
  whether) to expose this.
- **`checkHealth(tenantId)`** — a lightweight per-tenant `SELECT 1`,
  exposed for a future `/health/ready` aggregation. Deliberately **not**
  wired into `/health/ready` yet: no tenants exist at boot this phase, so
  there'd be nothing to check — wiring happens once a real caller needs
  tenant-DB health, rather than adding a check that's always vacuously
  true.

## Provisioning CLI

```
pnpm manar tenant:create --slug <slug> --name <name> [--residency UAE|CUSTOM_REGION|AIR_GAPPED] \
  [--allow-external-ai] [--allow-outbound-telemetry] [--allow-cloud-storage]
```

This is the **only** way to create a tenant this phase (Section 11 — no
`/admin/all-tenants` HTTP endpoint, no cross-tenant browsing surface, no
application-level super admin at all). `--allow-*` flags default to
`false` — the safest posture — matching `Tenant`'s schema defaults.

Built via `nest-commander` (`src/cli.ts`, `src/cli/`), sharing
`DatabaseModule` with the HTTP app but not `AppModule`'s HTTP-specific
wiring (Fastify adapter, correlation-ID middleware, health endpoints).

## Data residency (Section 54)

`Tenant.residency` (`UAE | CUSTOM_REGION | AIR_GAPPED`) and the
`allowExternalAi` / `allowOutboundTelemetry` / `allowCloudStorage` booleans
are captured from day one, even though this phase only exercises `UAE` with
every flag at its safe default (`false`). This avoids a destructive schema
migration later, when a real policy engine starts reading these fields to
gate behavior per tenant.

## Pools and timeouts (5 Nov 2026)

Every Prisma client (control and each cached tenant client) has an explicit `pg` pool
(`src/database/pool-options.ts`):

| Variable                     | Default | Meaning                                                                                      |
| ---------------------------- | ------- | -------------------------------------------------------------------------------------------- |
| `DB_POOL_MAX_CONTROL`        | 5       | Connections of the control pool                                                              |
| `DB_POOL_MAX_TENANT`         | 2       | Connections of each tenant client (up to `TENANT_DB_CLIENT_CACHE_MAX` of them)               |
| `DB_POOL_CONNECT_TIMEOUT_MS` | 3000    | Wait for a free connection / TCP connect; then the request fails (503, see below)            |
| `DB_QUERY_TIMEOUT_MS`        | 35000   | Client-side bound on one query, all pools (PgBouncer-safe)                                   |
| `DB_STATEMENT_TIMEOUT_MS`    | 30000   | Server-side `statement_timeout` for the TENANT pools only (0 = off); worker chart uses 120 s |

An exhausted pool, a client query timeout, "too many clients" (53300), a cancelled statement (57014,
55P03) or a Prisma transaction start timeout (P2028) answers **503** `enforcement_dependency_unavailable`
(`getClient` via `failClosed`; any other handler via `ErrorEnvelopeFilter`), never a hang.
A Prisma P2028 answers 503 only when it says the transaction could not be **started**; an expired or
closed transaction stays a 500. A TCP connect timeout ("Connection terminated due to connection
timeout") is a 503 like the pool-wait timeout.

**The control pool sends no startup parameters.** Production reaches the control DB through Azure
PgBouncer (`POOLED_CONTROL_DATABASE_URL`, port 6432, `?pgbouncer=true`) whose `ignore_startup_parameters`
is empty, so a `statement_timeout` startup parameter fails every connection with `08P01`. The control
timeout is set on the role instead (`ALTER ROLE manar_api IN DATABASE manar_control SET
statement_timeout = '30s'`, manar-infra#192) and the client `DB_QUERY_TIMEOUT_MS` still bounds each
query. Tenant pools connect directly and do send it.

Evicting a tenant client from the LRU cache does not cut queries still running on it: the pool is
disconnected `DB_QUERY_TIMEOUT_MS` + 5 s later (every query is bounded by that), and concurrent cache
misses for one tenant share a single client build.

### Connection budget

Postgres `max_connections` is 859. Every consumer counts (replicas from the production overlay,
manar-infra `clusters/azure-uaenorth`; there is no HPA today). Enforced by
`src/database/connection-budget.spec.ts`.

| Consumer                                                          | Formula                                  | Ceiling  |
| ----------------------------------------------------------------- | ---------------------------------------- | -------- |
| manar-api tenant pools (2 Nest apps x 2 pods)                     | 4 x `CACHE_MAX` 50 x `POOL_MAX_TENANT` 2 | 400      |
| manar-api-worker tenant pools (1 app x 1 pod)                     | 1 x 50 x 2                               | 100      |
| Control DB through PgBouncer (`default_pool_size`)                | capped by the pooler, not by pod x pool  | 50       |
| Keycloak (2 replicas x Agroal 100)                                | 2 x 100                                  | 200      |
| Temporal (4 services x 2 stores x `maxConns` 20)                  | 4 x 2 x 20                               | 160      |
| OpenFGA (2 replicas x `maxOpenConns` 30)                          | 2 x 30                                   | 60       |
| manar-site, manar-fleet, fleet service (1 replica, pg default 10) | 3 x 10                                   | 30       |
| **Sum of every ceiling at once**                                  |                                          | **1000** |

The 1000 is not reachable: a tenant client only holds server connections while it has queries in
flight (idle connections close after 10 s), and Keycloak, Temporal and OpenFGA sit far below their
maxima. The spec therefore counts the tenant pools at 50% simultaneous use (250), which gives
**750 of 859 (87%), headroom 109**, and fails above 90%. If k6 numbers or `pg_stat_activity` show tenant
use closer to the ceiling, lower `TENANT_DB_CLIENT_CACHE_MAX` (each step of 5 frees 40 connections at
today's replicas) before raising any other number. Changing a replica count in the overlay changes
this table.

### PgBouncer for tenant databases: not switched

Checked every session-level feature. Tenant request paths use none (all advisory locks are
`pg_advisory_xact_lock`, no `LISTEN`, `SET`, temp tables or cursors), so transaction pooling would
work for them. We still keep tenant DBs on the direct port because: provisioning and migrations
(`CREATE DATABASE`, `prisma migrate deploy` with its session advisory lock) need a direct
connection, which would mean two URLs per tenant; PgBouncer can reject the `statement_timeout`
startup parameter; and one pooler pool per tenant database multiplies server connections anyway.
`CONTROL_DATABASE_URL` in production already points at PgBouncer (transaction pooling, 6432). Anything
that needs a session on the control DB (`LISTEN`, session advisory locks) must use a direct URL;
`EdgePeerService` opens its `LISTEN` on `CONTROL_DATABASE_URL`; behind transaction pooling it receives no notifications, and only its 5 s fallback poll keeps long-poll waiters current (follow-up: give it a direct URL).

## Known limitations (this phase)

- No automatic rollback if `provisionTenant` fails after the control-DB
  rows exist (e.g. `CREATE DATABASE` or the tenant migration fails) — the
  tenant is left in `PROVISIONING` for manual inspection. A retry with the
  same slug will fail (the slug is already taken); operators must manually
  investigate and either fix the underlying database, drop it via
  `dangerouslyDropTenantDatabase` after transitioning to `DELETED`, or
  choose a new slug.
- `dangerouslyDropTenantDatabase` has no CLI/API surface this phase —
  intentional (see above); it exists so a later admin-tooling phase has
  somewhere correct to call from.
- `checkHealth` is not wired into `/health/ready`.
- `OPENBAO` is a valid `SecretReference.provider` enum value but has no
  implementation yet — resolving one throws from `EnvSecretProvider`.
