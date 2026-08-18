# Phase 8: Approval Engine (Temporal) — Design

Status: Approved (autonomous execution)
Scope: `manar-api` only
Depends on: Phase 7b (`POST /agent/v1/tools/invoke`, `AuthorizationService`
yielding `REQUIRE_APPROVAL`, `CredentialBrokerService`)

## Purpose

Sections 27, 28, 31: give `REQUIRE_APPROVAL` (a dead end since Phase 6) a
real fulfillment path — a durable Temporal workflow, a human decision
endpoint, and a short-lived signed grant that lets the agent's retried
request actually execute, single-use and exactly parameter-bound
(Section 80: approval replay and parameter-binding are mandatory
invariants).

## Flow (must match this exactly — it's what makes replay/parameter-binding provable)

1. Agent calls `POST /agent/v1/tools/invoke` → pipeline resolves
   `REQUIRE_APPROVAL` → server creates `ApprovalRequest`, starts a
   Temporal `ApprovalWorkflow`, returns
   `{ status: 'PENDING_APPROVAL', approvalId }`. **No tool call happens
   yet** — this is Section 80's "pending action cannot execute before
   approval" invariant.
2. Human calls `POST /approvals/:id/decide { decision, reason }`
   (JWT-guarded, role `APPROVER`/`SECURITY_ADMIN`/`TENANT_OWNER`) →
   signals the running workflow with the decision.
3. On `DENY`: workflow completes, `ApprovalRequest.status = DENIED`.
4. On `APPROVE`: the workflow (in an **Activity**, not workflow code —
   Section 28) **re-evaluates** before issuing anything: task still
   active/unexpired/under execution limit, agent still `ACTIVE`, the
   policy version that produced the original decision is still the
   published one (if the policy changed underneath the pending approval,
   don't trust the stale decision — re-run `PolicyEngine`/`RiskEngine`
   against current state). This is Section 27's explicit "don't assume
   an action remains safe because approval happened N minutes ago."
   If re-evaluation still supports approval, issue a short-lived signed
   `AuthorizationGrant` (Section 31: id/`jti`, tenant, agent, task, tool,
   action, resource, policy version, risk score, `issuedAt`, `expiresAt`
   — short, e.g. 5 minutes — and a `parameterHash` binding it to the
   _exact_ request params from the original `ApprovalRequest`).
   `ApprovalRequest.status = APPROVED`.
5. Agent polls `GET /agent/v1/approvals/:id`; once `APPROVED`, the
   response includes the grant token. Agent retries
   `POST /agent/v1/tools/invoke` with the same body plus `grantToken`.
6. Pipeline: if a `grantToken` is present, validate it (signature,
   unexpired, unconsumed, unrevoked, and — critically —
   `parameterHash` matches a hash computed from _this_ request's
   `taskId`/`toolId`/`actionId`/`resource`/`params` exactly). If it
   doesn't match (params changed even slightly), reject — this is the
   parameter-binding invariant. Still re-check kill-switch-equivalent
   fail-closed conditions (task/agent still active — no kill-switch
   system exists yet, that's a later phase, but don't skip the checks
   that DO exist). On a valid, matching grant: skip the
   `REQUIRE_APPROVAL` gate (already satisfied), mark the grant consumed
   (single use — Section 80's approval-replay invariant), proceed to
   `CredentialBrokerService.invoke` exactly as the `ALLOW` path already
   does.
7. A consumed, expired, or parameter-mismatched grant used again → DENY.

## Data model (tenant DB)

- `ApprovalRequest`: `id`, `taskId`, `agentId`, `toolId`, `actionId`,
  `resource`, `params` (Json — same params originally submitted to
  `/tools/invoke`), `riskScore`, `policyVersionId` (FK — the version
  that triggered the requirement), `status` (enum `PENDING | APPROVED |
DENIED | EXPIRED`), `requestedAt`, `expiresAt` (approval requests
  themselves expire if nobody decides — pick and document a value, e.g.
  30 minutes), `temporalWorkflowId`.
- `ApprovalDecision`: `id`, `approvalRequestId` (FK), `approverId` (FK
  `UserProfile`), `decision` (enum `APPROVE | DENY`), `reason`,
  `decidedAt`. Modeled as 1:many even though this phase only ever
  produces one row per request (decision #33: one approver) — this is
  what lets a future N-of-M approval chain be added without a schema
  migration; don't build N-of-M logic itself, just don't foreclose it.
- `AuthorizationGrant`: `id` (this IS the `jti`), `approvalRequestId`
  (FK), `taskId`, `agentId`, `toolId`, `actionId`, `resource`,
  `parameterHash`, `policyVersionId`, `riskScore`, `issuedAt`,
  `expiresAt`, `consumedAt` (nullable), `revokedAt` (nullable, unused
  this phase — kill-switch-driven grant revocation is a later phase, but
  the column existing now means that phase doesn't need a migration).

Migration.

## Temporal

Add Temporal to `deploy/docker-compose.yml` (research current official
Temporal docker-compose setup — it's a multi-component system: server,
UI, a persistence store; check whether it can reuse the existing Postgres
or needs its own, per current docs). Add `@temporalio/client`/`worker`/
`workflow`/`activity` packages.

**The Temporal worker must run as its own process/entrypoint** (e.g.
`src/worker.main.ts`, its own `pnpm worker` script, its own Dockerfile
`CMD` or a second stage) — not embedded in the same event loop as the
Fastify HTTP server. Workflow code contains no I/O (per Section 28); all
DB/HTTP/crypto work happens in Activities the workflow calls.

`ApprovalWorkflow(approvalRequestId)`: waits (via a Temporal signal,
`decide`) for a human decision or its own timeout (`expiresAt`), then
runs the re-evaluation + grant-issuance Activity (on approve) or just
records denial (on deny/timeout → `EXPIRED`).

## Testing

Use `@temporalio/testing`'s time-skipping test environment for the
workflow's own logic (approve path, deny path, timeout/expiry path) per
Section 28's "add unit/integration coverage for workflows" — don't rely
solely on real-time e2e tests for the timeout case, that's what the
time-skipping environment is for.

E2e (real Postgres/Keycloak/OpenBao/OpenFGA/Temporal, real SDK):

- Full flow: invoke → `PENDING_APPROVAL` → decide APPROVE → poll →
  grant returned → retry invoke with grant → tool actually executes
  (against Phase 7b's test fixture, same pattern Phase 7b used).
- Decide DENY → `ApprovalRequest.status = DENIED`, retry invoke without
  a grant → still `REQUIRE_APPROVAL` or explicit denial, never executes.
- **Approval replay**: reuse an already-consumed grant → denied.
- **Parameter binding**: get a grant for one `resource`/`params`, retry
  with different `params` using the same grant → denied (Section 80
  mandatory invariant — do not skip).
- Grant used after its own short expiry → denied.
- Approval request itself expires (nobody decides in time) → workflow
  completes as `EXPIRED`, no grant ever issuable for it.
- Policy changed between request and decision (republish a stricter
  policy mid-flight) → re-evaluation at approval time catches it, grant
  is not issued even though the human clicked approve (proves Section
  27's re-evaluation requirement is real, not decorative).
- Existing Phase 5/6/7 e2e suites still pass unmodified.

## Docs

`docs/approvals.md` (the flow above, the grant format, why re-evaluation
happens at approval time not just request time).

## Out of scope this phase

- N-of-M / multi-approver chains (schema allows it later, logic doesn't
  exist)
- Approval dashboard UI (Phase 11) — decision is an API call only
- Kill-switch-driven grant revocation (dedicated later phase) — the
  `revokedAt` column exists, nothing sets it yet
- Slack/Teams/email/ServiceNow approval channels
