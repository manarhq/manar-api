# ADR-0013: per-tenant catalog (feature flags, packs, LLM route) set by Manar staff

- Status: proposed (9 Oct 2026, manar-api `feat/platform-catalog`)
- Context owner: V2 (admin console v2, catalog); reviewer: Mohamed

## Context

The staff admin console (`docs/hq/ADMIN-V2-PLAN.md`) manages what each tenant may use: the
console assistant, the watcher, packs, the agent LLM proxy, and which model a tenant's prompts go
to. Changing any of these is propose-then-approve by two staff members in manar-fleet. manar-api
had no per-tenant switch for any of them: the assistant and LLM proxy were on for every tenant,
the model was one per deployment, and nothing tied a task to a pack.

## Decision

1. **Store.** One control-DB row per tenant, `tenant_catalogs`: `features` (only the keys staff
   set), `packs` (`{ id, version, enabled }[]`), `model` (`{ provider, model, uaeResidency,
monthlyTokenQuota }` or null). Parsed with zod on every read. No row = unmanaged: every
   feature keeps its pre-catalog default (on), no pack is enabled, the deployment's model.
2. **API for manar-fleet.** `GET` and `PATCH /platform/v1/tenants/:id/catalog`, same guard as
   ADR-0010 (platform client only). `PATCH` merges features, upserts packs by id and replaces the
   model; every write is logged and recorded as `catalog.updated` in the tenant's audit chain.
   `GET` also returns this month's model tokens and the tenant's registered tools with the
   credential expiry an operator recorded in tool metadata (`credentialExpiresAt`).
3. **Enforcement, fail closed.** A catalog read failure or a malformed row denies
   (`enforcement_dependency_unavailable` / 503); a disabled feature is never on.
   - Decision path, step 3b (also at grant redemption): the built-in `manar` connector needs
     `watcher` (`watcher_disabled`); a task with `packId` needs `packs` (`packs_disabled`) and its
     pack enabled (`pack_not_enabled`). Reads PostgreSQL only.
   - Agent runtime gate (tool manifest, MCP, LLM proxy): the same pack rule.
   - LLM proxy and console assistant: `llm_proxy` / `assistant` on; with a tenant model, an
     external provider (Azure OpenAI, Core42 Compass) needs the tenant's `allowExternalAi`, a
     UAE-resident tenant needs `uaeResidency` declared on the model, and the month's tokens must
     be under the quota (Redis, the limits store). Every completion's tokens are counted per
     tenant per UTC month; a counter that cannot be written refuses the answer.
   - `POST /tasks` with `packId` is refused (403) unless the pack is enabled. Delegated children
     inherit the parent's `packId`.
4. **Core42 Compass** is a third upstream (OpenAI-compatible, bearer key from
   `CORE42_API_KEY`), used only when a tenant's catalog picks it. Not yet run against a live
   Compass endpoint.

## Consequences

- Tenant migration `add_task_pack` (nullable `tasks.packId`): run `pnpm manar tenants:migrate`
  on upgrade; until then the new code fails closed on that tenant's task reads. Older API code
  reads the column-added table unchanged. Control migration `add_tenant_catalog` adds a table only.
- Rollback: revert the code; both migrations are additive (drop `tenant_catalogs` and
  `tasks.packId` only if the catalog is abandoned).
- Endpoints and keys stay one per provider per deployment. Two Azure customers on one hosted
  deployment would need per-tenant endpoints and keys in OpenBao.
- The quota is check-then-add: concurrent calls can overshoot by at most one call each.
- Enforcement labels: no label is upgraded. A disabled feature narrows what is `governed`.
