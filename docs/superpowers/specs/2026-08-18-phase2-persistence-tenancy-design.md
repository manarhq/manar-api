# Phase 2: Persistence & Tenancy — Design

Status: Approved (autonomous execution authorized by user; no interactive
review gate this phase)
Scope: `manar-api` only, plus new local dev infra (Postgres via
docker-compose)

## Purpose

Implement the control-plane/tenant database split from Section 10 of the
master prompt: a control database holding only provisioning/routing
metadata, and one fully isolated Postgres database per tenant holding that
tenant's domain data. No domain modules (auth, agents, tasks, ...) yet —
this phase builds the mechanism those modules will sit on top of.

## Local infra

New `deploy/docker-compose.yml` in `manar-api` (grows phase-by-phase as
later phases need Keycloak/OpenFGA/OpenBao/Kafka/Temporal/Redis/
OpenSearch — only Postgres is added now, per YAGNI): a single Postgres 17
container. Control DB and tenant DBs are separate _databases_ on this one
Postgres server for local dev (isolation is enforced by Postgres's
database boundary — there is no SQL surface for cross-database queries
without `dblink`/FDW, which this project never uses). Production may later
split tenant DBs across separate server instances without changing the
application-level contract (`TenantDatabaseManager` resolves a connection
string per tenant; it doesn't assume same-server).

`pnpm infra:up` / `pnpm infra:down` wrap `docker compose -f deploy/docker-compose.yml`.

## Control DB schema (`prisma/control.prisma`)

- `Tenant`: `id`, `slug` (unique), `name`, `status` (enum:
  `PROVISIONING | ACTIVE | SUSPENDED | DEPROVISIONING | DELETED`),
  data-residency fields per Section 54 from day one —
  `residency` (enum: `UAE | CUSTOM_REGION | AIR_GAPPED`),
  `allowExternalAi`, `allowOutboundTelemetry`, `allowCloudStorage`
  (booleans, default false — safest default), `createdAt`, `updatedAt`.
- `TenantDatabaseBinding`: one-to-one with `Tenant`, `databaseName`
  (unique), `secretReferenceId` (FK), `provisioningStatus` (reuses the
  same status enum as `Tenant.status` scoped to DB provisioning),
  `provisionedAt`, `lastMigratedAt`, `lastMigrationVersion`,
  `deploymentMetadata` (Json — host/port/engine-version notes; folded in
  here rather than a separate 1:1 model per Section 70's normalization
  guidance).
- `SecretReference`: `id`, `tenantId` (FK), `kind` (enum, only
  `DATABASE_CREDENTIAL` for now), `provider` (enum: `ENV` now, `OPENBAO`
  reserved for Phase 4/17), `reference` (opaque string — for `ENV` this is
  the env var name holding the base connection URL), `createdAt`.

No business/security data (agents, tasks, policies, audit, etc.) is ever
stored here — enforced by review, not by a runtime check, since Prisma
schemas are compile-time-fixed.

## Tenant DB schema (`prisma/tenant.prisma`)

Datasource + generator blocks only, **no models yet**. An initial
migration establishes the (empty) schema. Phase 3 onward add their own
models here incrementally. This is deliberate: inventing placeholder
domain models now to have "something to test" would be exactly the kind
of premature scaffolding the project's guidelines forbid. Isolation is
proven structurally instead (see Testing).

## `SecretProvider` interface

```ts
interface SecretReferenceDescriptor {
  provider: 'ENV' | 'OPENBAO';
  reference: string;
}
interface SecretProvider {
  resolve(ref: SecretReferenceDescriptor): Promise<string>;
}
```

`EnvSecretProvider` (only implementation this phase): reads a base
Postgres connection URL from the named env var, and `TenantDatabaseManager`
substitutes the tenant's `databaseName` into it. `OpenBaoSecretProvider`
is a later swap-in (Phase 4/17) behind the same interface — no caller
changes when it arrives.

## `TenantDatabaseManager`

- `resolveTenant(tenantId)`: loads `Tenant` + `TenantDatabaseBinding` from
  the control DB.
- `getClient(tenantId)`: returns a cached tenant-scoped Prisma client or
  creates one (`new TenantPrismaClient({ datasourceUrl })`), bounded LRU
  cache (configurable max, default 50), idle eviction disconnects the
  client cleanly. Never an unbounded per-request client (Section 10).
- `provisionTenant({ slug, name, residency, ... })`: creates the Tenant +
  TenantDatabaseBinding + SecretReference rows, issues `CREATE DATABASE`
  against the Postgres server via the control connection, runs
  `prisma migrate deploy` for `tenant.prisma` against the new database
  (spawned as a child process with `DATABASE_URL` set to the resolved
  tenant URL), updates `provisioningStatus`/`lastMigratedAt`.
- `deprovisionTenant(tenantId)`: transitions status to
  `DEPROVISIONING`/`DELETED` and evicts any cached client. Does **not**
  drop the database automatically — an explicit, separately-invoked,
  clearly-named destructive operation exists for that (never wired into
  any normal command path), consistent with the project's stance against
  silent destructive defaults.
- Health check: a lightweight per-client `SELECT 1` exposed for the
  `/health/ready` endpoint to aggregate later (not wired to `/health/ready`
  yet — no tenants exist at boot, nothing to check; wiring happens once a
  real caller needs tenant-DB health, avoiding a check that's always
  vacuously true).

## Provisioning CLI

`nest-commander`-based command: `pnpm manar tenant:create --slug <s> --name <n> --residency <r>`.
This is the only way to create a tenant (Section 11 — no
`/admin/all-tenants` API, no cross-tenant HTTP surface at all this phase).

## Testing strategy

Structural isolation tests (Vitest, against the real local Postgres via
`infra:up` — not mocked, per the project's "no mocking database in tests
that must catch integration failures" default and Section 80's mandatory
tenant-isolation invariant test):

1. Provision two tenants; assert they get distinct `databaseName`s and
   distinct `SecretReference`s.
2. Each tenant's Prisma client's `SELECT current_database()` returns that
   tenant's own database name, never the other's.
3. `TenantDatabaseManager` never returns the same live client instance for
   two different tenant IDs, and the LRU cache evicts under load (test
   with a small configured max to keep it fast).
4. Attempting to resolve an unknown/deprovisioned tenant ID fails closed
   (throws), never silently falls back to the control DB or another
   tenant.
5. Provisioning is idempotent-safe: re-provisioning an existing slug fails
   with a clear conflict error rather than creating a duplicate database.

## Docs

`docs/tenant-isolation.md` (required by Section 87) explaining the
control/tenant DB split, the `SecretProvider` swap point, and why
isolation is structural rather than a `WHERE tenantId = ...` filter.
`docs/dependency-decisions.md` gets new entries for every dependency added
(Prisma, `nest-commander`, `pg`, whatever Postgres image/version is
selected after checking current official docs).

## Out of scope this phase

- Any tenant DB domain model beyond the empty schema
- Wiring tenant DB health into `/health/ready`
- OpenBao-backed secrets (interface only)
- Actual tenant deletion (drop database) automation
- Keycloak/auth (Phase 3)
