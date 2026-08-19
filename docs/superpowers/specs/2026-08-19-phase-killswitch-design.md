# Phase: Kill Switches (all five scopes) — Design

Status: Approved (autonomous execution) — **HIGH PRIORITY, gap-closing**.
Section 24's authorization pipeline diagram always included "check
global/tenant/agent/tool kill switches" as a step, and Section 32
mandates all five scopes, but no phase 1-10b actually built this —
Phase 4 only shipped per-agent revocation and Phase 5 only per-task
revocation. The mandatory MVP acceptance scenario (master spec Section
2, steps 32-33) and Section 80's invariant tests explicitly require a
real kill switch. This must land before Phase 13 (complete demo).
Scope: `manar-api` only
Depends on: Phase 5 (`AuthorizationService`), Phase 8 (`GrantService`/
`AuthorizationGrant`), Phase 9a (`AuditService`)

## Purpose

Section 32: kill switches at five scopes — platform/deployment, tenant,
agent group, agent, tool — each immediately enforceable on new
authorization decisions AND capable of invalidating already-issued
authority where required. Not a config flag nobody checks: this must sit
directly in the hot authorization path.

## Data model (tenant DB, except platform scope)

- `KillSwitch`: `id`, `scope` (enum `TENANT | AGENT_GROUP | AGENT |
TOOL`), `targetId` (nullable — null only makes sense for a
  tenant-wide switch where the tenant itself is implicit via the tenant
  DB; for `AGENT_GROUP`/`AGENT`/`TOOL` this is the specific group/agent/
  tool id), `active` (bool), `reason`, `activatedBy` (FK `UserProfile`),
  `activatedAt`, `deactivatedBy` (nullable), `deactivatedAt` (nullable).
- **Platform scope is different**: it's not tenant data (it affects
  every tenant, including ones whose control-DB row might itself be
  compromised) — model it as a row in the **control DB** instead
  (`PlatformKillSwitch`: `active`, `reason`, `activatedBy`,
  `activatedAt` — this is the one thing in this whole product that
  legitimately needs a cross-tenant check, and it belongs in the control
  DB precisely because Section 10/11 already established the control DB
  as the one place operational metadata like this lives, distinct from
  tenant business data). `TenantDatabaseManager` or a new thin
  `PlatformKillSwitchService` reads this without touching any tenant DB.

Migrations (both control and tenant schemas).

## Wiring into `AuthorizationService`

Add a kill-switch check as an early pipeline step (before the ancestor-
chain walk that already exists — if the platform or tenant is killed,
don't bother evaluating anything else):

1. Platform kill switch active → DENY (checked first, cheapest, applies
   to literally everything).
2. Tenant kill switch active → DENY.
3. The requesting agent's kill switch active → DENY.
4. Any `AgentGroup` the requesting agent belongs to has an active kill
   switch → DENY.
5. The specific `Tool` being invoked has an active kill switch → DENY
   (only meaningful for `/agent/v1/tools/invoke`, not the bare
   `/agent/v1/authorize` decision endpoint if it doesn't already know
   the tool — check where this fits given the real current pipeline
   order, don't force it in the wrong place).

## Wiring into grant redemption (`GrantService`) — Section 32's harder requirement

A grant issued _before_ a kill switch activates must become unusable
immediately, not just new authorization requests. `GrantService`'s
existing validate-and-consume path (Phase 8) must re-check all
applicable kill switches (platform/tenant/agent/agent-group/tool for
that grant's specific agent+tool) at redemption time, not just rely on
whatever was true when the grant was issued. Write the mandatory test
for this exact sequence: agent successfully uses a grant once → kill
switch activated → agent retries with a still-unexpired, still-unconsumed
grant it already has in hand → denied (Section 32: "existing outstanding
grants must become unusable").

## Admin endpoints (JWT-guarded)

- `POST /kill-switches/platform` (role: a genuinely privileged role —
  this is the single most destructive lever in the product; use
  whatever this codebase's most restrictive existing role is,
  `TENANT_OWNER`/`SECURITY_ADMIN` — note platform scope is
  cross-tenant-impacting so consider whether it even belongs behind a
  per-tenant role at all, or should be a separate operator-only
  mechanism; make a reasoned decision and document it, this is exactly
  the kind of "no application-level super admin" tension Section 11
  flags — resolve it, don't ignore it).
- `POST /tenants/kill-switch` (`TENANT_OWNER`/`SECURITY_ADMIN`).
- `POST /agent-groups/:id/kill-switch`, `POST /agents/:id/kill-switch`,
  `POST /tools/:id/kill-switch` (same roles).
- Each has a corresponding deactivate endpoint. Every activation/
  deactivation writes an `AuditEvent` (`kill_switch.activated`/
  `kill_switch.deactivated`, Phase 9a's catalog already names these)
  via `AuditService.recordSafely()`.

## Testing (Section 80's mandatory kill-switch invariant, verbatim)

1. Agent receives usable authority (task grant, successful action).
2. Kill switch activated (test each of the 4 tenant-scoped kinds
   separately: tenant, agent group, agent, tool — plus platform).
3. Retry the exact same previously-successful action → denied,
   immediately, no propagation delay.
4. The already-issued `AuthorizationGrant` from before activation is
   also now unusable (the harder grant-redemption test above).
5. Deactivating the kill switch restores the agent's ability to request
   authorization again through the normal pipeline (doesn't resurrect
   the _specific consumed/expired_ grant, but proves the switch itself,
   not some other side effect, was what was blocking).
6. A kill switch on Agent A does not affect Agent B (scope precision —
   don't over-broadly deny).
7. Platform kill switch denies across every tenant (requires testing
   with at least two provisioned tenants).

## Out of scope this phase

- Any UI (Phase 11b+) — API only
- Kill switches as a Temporal-orchestrated propagation mechanism across
  multiple API replicas beyond what a direct DB check already guarantees
  (a DB-backed check on every request IS immediate and correct for this
  architecture — don't over-engineer a pub/sub propagation layer on top,
  the check-on-every-request approach has no propagation delay by
  construction)
