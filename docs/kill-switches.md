# Kill switches

This is `manar-api`'s implementation of the Kill Switches phase:
`docs/superpowers/specs/2026-08-19-phase-killswitch-design.md`, Section 32.
Section 24's authorization pipeline diagram always included a kill-switch
check, but no phase before this one actually built it — Phase 4 only
shipped per-agent revocation and Phase 5 only per-task revocation. This
phase closes that gap at all five scopes: platform/deployment, tenant,
agent group, agent, and tool — each immediately enforceable on new
authorization decisions _and_ capable of invalidating already-issued
authority.

## Data model

Four tenant-scoped kill switches live in the tenant DB
(`prisma/tenant.prisma`, migration `20260819010028_add_kill_switches`):

- **`KillSwitch`**: `scope` (`TENANT | AGENT_GROUP | AGENT | TOOL`),
  `targetId` (nullable — `null` only for `TENANT` scope, where the tenant
  itself is implicit via the tenant database; otherwise the specific
  `AgentGroup.id`/`Agent.id`/`Tool.id`), `active`, `reason`,
  `activatedBy`/`activatedAt`, `deactivatedBy`/`deactivatedAt`. One row per
  `(scope, targetId)` pair, toggled in place by activate/deactivate rather
  than appended as history — both the activation and deactivation fields
  live on the same row, matching the design spec's field list exactly.

The fifth scope is different: **`PlatformKillSwitch`** lives in the
**control DB** (`prisma/control.prisma`, migration
`20260819010017_add_platform_kill_switch`) — a singleton row (fixed id
`"singleton"`, the same convention `AuditChainState` already uses),
because it is genuinely cross-tenant: it must remain checkable even for a
tenant whose own control-DB row or database might itself be compromised,
and it belongs in the control DB precisely because Section 10/11 already
established that split (`docs/tenant-isolation.md`). Its
`activatedBy`/`deactivatedBy` are free text, not a `UserProfile` FK — the
control DB has no `UserProfile` table at all (that's tenant data).

`src/kill-switches/platform-kill-switch.service.ts` is a thin
control-DB-only reader/writer (`PlatformKillSwitchService`), never
touching any tenant DB — matching the design spec's explicit instruction.

## `KillSwitchService.checkAll` — the one implementation both hot paths call

`src/kill-switches/kill-switch.service.ts`'s `checkAll(tenantClient,
tenantId, { agentId, toolId? })` is the single lookup both
`AuthorizationService.authorize` and `AuthorizationService.authorizeRedemption`
call — one implementation of "is this agent/tool/tenant/platform currently
killed," not two copies that could drift. Cheapest-first, short-circuiting
on the first active switch found:

1. **Platform** (`PlatformKillSwitchService.isActive()`, control DB) —
   checked first, cheapest, applies to literally every tenant.
2. **Tenant** (`scope: TENANT, targetId: null`).
3. **Agent** (`scope: AGENT, targetId: agentId`).
4. **Agent group(s)** — every `AgentGroup` the agent is a member of
   (`AgentGroupMembership`), any one of which having an active switch
   denies.
5. **Tool** — only when a `toolId` is given _and_ it resolves against a
   real registered `Tool.name`. An opaque/unregistered `toolId` (Phase 5's
   long-standing contract — see `docs/authorization-model.md`) has no
   `Tool.id` for a `TOOL`-scope switch to ever target, so it's simply never
   killed for an unregistered tool, exactly like `ToolRegistryService`'s
   existing "may or may not resolve" posture elsewhere.

## Wiring into `AuthorizationService` — step 0

`AuthorizationService.authorize` (`src/authorization/authorization.service.ts`)
gets a new step 0, run **before the task is even resolved** (before the
existing step 1's `getTaskOrThrow`) — none of the five kill-switch checks
need the task at all, and this is the cheapest, most fundamental "don't
bother evaluating anything else" gate in the whole pipeline, exactly as the
design spec asks ("before the ancestor-chain walk ... if the platform or
tenant is killed, don't bother evaluating anything else"). `request.toolId`
is already known at this point for both callers of this pipeline
(`POST /agent/v1/authorize` and `POST /agent/v1/tools/invoke`'s no-grant
path) — Phase 5's `AuthorizeRequest.toolId` was always part of the request
body, so the tool-scope check applies to both endpoints identically; there
is no separate "the bare `/authorize` endpoint doesn't know the tool" case
in this codebase's actual pipeline (unlike, say, `CredentialBrokerService`'s
own separate, _later_ tool-registry resolution on the ALLOW path, which
this step does not depend on or duplicate).

A kill-switch DENY reuses the pipeline's existing "specific, non-leaky
reason" posture (steps 1-4): `platform_kill_switch_active`,
`tenant_kill_switch_active`, `agent_kill_switch_active`,
`agent_group_kill_switch_active`, `tool_kill_switch_active` — deterministic
app-layer state, safe to expose, same as `not_assigned_agent`/
`forbidden_action`/etc.

## Wiring into `GrantService` — the harder requirement

Section 32's actual hard requirement: an `AuthorizationGrant` issued
_before_ a kill switch activates must become unusable immediately, not
just block _new_ `/agent/v1/authorize`/`/agent/v1/tools/invoke` requests.
A `grantToken` retry of `POST /agent/v1/tools/invoke` goes through
`GrantService.verifyGrant` (binds the grant to this exact request; the
claims and the persisted `AuthorizationGrant` row must both match it) and
then `AuthorizationService.authorizeRedemption`, which re-runs the whole
pipeline, `checkAll` first, before the atomic `consumedAt` update (2026-10-07,
S6/F7). This means:

- The check runs against _current_ state at redemption time, never
  whatever was true at issuance.
- A denial here happens **before** the grant is ever marked consumed — so
  deactivating the kill switch afterward genuinely restores the grant's
  usability (it was never consumed, just repeatedly blocked while the
  switch was on), which is exactly what proves the switch itself — not
  some other side effect — was the blocker (the design spec's mandatory
  scenario 5).
- No `PolicyEngine`/`RiskEngine` re-run and no second `executionCount`
  increment happen here either way (unchanged from before this phase) —
  the kill-switch check is additive, not a re-decision of anything else.

## Admin endpoints — the platform-scope role-gating decision

`src/kill-switches/kill-switches.controller.ts` exposes activate/deactivate
pairs for all five scopes:

```
POST /kill-switches/platform(/deactivate)
POST /tenants/kill-switch(/deactivate)
POST /agent-groups/:id/kill-switch(/deactivate)
POST /agents/:id/kill-switch(/deactivate)
POST /tools/:id/kill-switch(/deactivate)
```

Every route is `JwtAuthGuard`+`RolesGuard`-gated to `SECURITY_ADMIN`/
`TENANT_OWNER` — the same "a role capable of managing agents" bar
`AgentsController`/`TasksController` already use.

**The platform endpoint's tension (Section 11 — "no application-level
super admin")**: a per-tenant role, however privileged, is scoped by
construction to whichever tenant's Keycloak realm issued the caller's
token (`JwtAuthGuard` resolves `AuthContext.tenant` from the token's
issuer — see `docs/human-auth.md`). This codebase has never defined, and
never built, a role that spans tenants. Gating the single most
destructive/cross-tenant lever in the product behind _only_ a per-tenant
role would let any one tenant's admin deny every other tenant — an
application-level super admin materializing by accident, exactly what
Section 11 forbids.

**Decision**: `POST /kill-switches/platform`(`/deactivate`) requires
`SECURITY_ADMIN`/`TENANT_OWNER` in the caller's own tenant **and**
`PlatformOperatorGuard` (`src/kill-switches/platform-operator.guard.ts`) —
a second, genuinely separate credential (`PLATFORM_KILL_SWITCH_OPERATOR_TOKEN`,
sent as `X-Platform-Operator-Token`) that is never distributed through any
tenant's Keycloak realm/RBAC at all. This mirrors the "operator-only,
outside the application's own RBAC" trust boundary
`CONTROL_DATABASE_URL`/`TENANT_DB_BASE_URL` already sit behind, and is the
same posture that makes `pnpm manar tenant:create` CLI-only rather than a
`RolesGuard`-gated HTTP endpoint (`docs/tenant-isolation.md`) — the
difference here is that the design spec explicitly asks for
`POST /kill-switches/platform` to exist as a real HTTP endpoint (unlike
tenant creation), so this phase keeps it as one, just gated by a second,
orthogonal credential rather than relying on per-tenant RBAC alone. Still
requiring a valid per-tenant JWT (rather than _only_ the operator token)
keeps a real, attributable `UserProfile` actor for the audit trail this
endpoint's own tenant-DB `AuditEvent` records (see below) — an operator
token alone would have no human identity to attribute the action to.

## Audit

Every activation/deactivation, at every scope, writes a
`kill_switch.activated`/`kill_switch.deactivated` `AuditEvent`
(`src/audit/audit-event-types.ts`) via `AuditService.recordSafely`:

- The four tenant-scoped switches record into that tenant's own audit
  chain (`KillSwitchService.activate`/`deactivate` — the same call site
  that mutates the `KillSwitch` row).
- The platform switch's own row lives in the control DB (no audit chain
  there — audit chains are Phase 9a's tenant-DB-only concept), but the
  calling human is still a real, tenant-affiliated `AuthContext` —
  `KillSwitchesController` records the event into _that_ tenant's own
  audit chain (the normal per-request `tenantClient`/`tenantId` every
  other endpoint already uses), as a record of "this tenant's user pulled
  the platform-wide lever," not a nonexistent cross-tenant audit chain.

## Out of scope this phase

- Any UI (a later phase) — API only.
- A Temporal-orchestrated (or any other) propagation mechanism across API
  replicas beyond what `checkAll`'s direct DB read already guarantees on
  every request — a DB-backed check on every request already has zero
  propagation delay by construction; a pub/sub layer on top would be pure
  over-engineering for the invariant this phase actually needs.
- `AgentGroup` CRUD — this phase only adds the group-scope kill-switch
  endpoint itself (`AgentGroupMembership` already existed, unused, since
  Phase 4); creating/managing groups otherwise has no API yet.

## Testing

`test/kill-switches.e2e-spec.ts` runs every mandatory scenario from the
design spec's "Testing" section against real Postgres/Keycloak/OpenBao/
OpenFGA/Temporal (`pnpm infra:up`), reusing the real SDK
(`ManarAgent.enroll`/`.authorize`) for every ALLOW/DENY check and the same
raw-mTLS `/agent/v1/tools/invoke` + `/agent/v1/approvals/:id` +
in-process-Temporal-worker pattern `test/approvals.e2e-spec.ts` already
established for the one scenario needing a real grant:

1-4. Each of the four tenant-scoped kill kinds (tenant/agent/agent-group/
tool), individually: a previously-ALLOWed action retried immediately
after activation → denied with the specific reason; deactivating
restores the ALLOW. 5. **Grant redemption** (the harder requirement): an agent successfully
consumes one grant, then obtains a _second_, separate grant it does not
yet use; a kill switch activates; retrying with the still-unexpired,
still-unconsumed second grant → denied — proving `GrantService`
re-checks at redemption time, not just at issuance. Deactivating
restores that same grant's usability (it was never consumed while
blocked), confirming the switch itself was the blocker. 6. **Scope precision**: a kill switch on Agent A does not deny Agent B's
unrelated task in the same tenant. 7. **Platform scope**: activated across two independently provisioned
tenants, denies both; deactivating restores both. The exposure window
(activate → assert → deactivate) is kept minimal, wrapped in
`try`/`finally`, with a `beforeAll` safety net that force-deactivates
the switch up front in case a previous crashed run left it active — see
that spec file's own class doc comment for why this scope's real,
shared, cross-tenant state needs that care under Vitest's default
parallel file execution.

Phase 4-10b's existing e2e suites (18 files, 93 tests total including this
one) re-run and pass unmodified.
