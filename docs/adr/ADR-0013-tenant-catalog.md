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
   `GET` also returns this month's model tokens, the tenant's registered tools (name and kind)
   and its agents (for binding). Credential expiry has one source, OpenBao KV `custom_metadata`
   `expires_at`, served by the platform ops route, not here.
3. **Enforcement, fail closed.** A catalog read failure or a malformed row denies
   (`enforcement_dependency_unavailable` / 503); a disabled feature is never on.
   - **A task's pack** is its own `packId`, or the pack its agent is bound to (`packs[].agents`,
     set by staff through manar-fleet; an agent runs at most one pack). Binding the agent closes
     the gap where a tenant user creates a pack agent's task without `packId`: every task of a
     bound agent is a pack task, old ones included. A task naming another pack than its agent's
     is `pack_mismatch`.
   - Decision path, step 3b (also at grant redemption): the built-in `manar` connector needs
     `watcher` (`watcher_disabled`); a pack task needs `packs` (`packs_disabled`) and its pack
     enabled (`pack_not_enabled`). Reads PostgreSQL only.
   - Agent runtime gate (tool manifest, MCP, LLM proxy): the same pack rule; the `manar` tool is
     also left out of the manifest while `watcher` is off.
   - LLM proxy and console assistant: `llm_proxy` / `assistant` on. The external-AI and residency
     rules apply to the model actually used, the tenant's or the deployment default
     (`LLM_PROVIDER`): an external provider (Azure OpenAI, Core42 Compass) needs the tenant's
     `allowExternalAi`; a UAE-resident tenant needs a UAE-resident model (the tenant model's
     `uaeResidency`; for the default, Ollama counts as resident because it runs in the deployment,
     Azure only with `LLM_DEFAULT_UAE_RESIDENT=true`). The monthly quota is part of the tenant
     model; with the default model there is no quota. Tokens are counted per tenant per UTC month;
     a counter that cannot be written refuses the answer; an assistant chat stops at the next
     model round once the quota is spent.
   - `POST /tasks`: the task's pack is the requested one or the agent's; a mismatch or a pack
     that is not enabled is refused (403). Delegated children inherit the parent's `packId`.
   - **Writes** read, merge and write the row in one control-DB transaction holding the row lock
     (`INSERT ... ON CONFLICT DO NOTHING`, then `SELECT ... FOR UPDATE`), so two approved
     changes for the same tenant never undo each other. A pack entry may carry
     `expect: { enabled?, maxVersion? }`, checked under that lock; a mismatch is 409
     `catalog_precondition_failed` and nothing is written. manar-fleet sends it on publish
     (`enabled: true`, older version) and on enable (`maxVersion`), so a pack disabled in the
     deployment is never re-enabled by a publish and never moved back a version. The tenant audit event
     (`catalog.updated`) is written inside that transaction: no event, no change.
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
- A Fixio-style deployment whose default model is Azure OpenAI needs `LLM_DEFAULT_UAE_RESIDENT=true`
  and each UAE tenant's `allowExternalAi`, or its LLM calls are refused. The shared demo tenant uses
  the local Ollama default and is not affected.
- The usage counter's Redis client moves to the shared `redisClientOptions()` (TLS and auth) once
  that helper is on main.
- Enforcement labels: no label is upgraded. A disabled feature narrows what is `governed`.
