# Phase 5: Tasks, Delegation & OpenFGA — Design

Status: Approved (autonomous execution)
Scope: `manar-api` only
Depends on: Phase 4 (agent identity, mTLS, enrollment — delegation reuses
the enrollment mechanism for child agents)

## Purpose

Implement Sections 18-20: agents start with zero permanent authority and
receive narrowly scoped, expiring task authority; subagents can never
exceed their parent's authority; OpenFGA is the relationship-authorization
engine. This is the core security invariant of the whole product — treat
the delegation-subset and revocation-cascade tests as non-negotiable, not
nice-to-haves.

## Local infra addition

Add OpenFGA to `deploy/docker-compose.yml`, using its Postgres storage
engine (a new `openfga` database on the existing Postgres server, run
OpenFGA's migrate command against it — research current official OpenFGA
docs for the exact setup, don't guess) rather than in-memory storage, for
consistency with the "nothing ephemeral" posture the rest of local infra
already follows.

## Data model (tenant DB)

- `Task`: `id`, `name`, `description`, `requesterId` (FK `UserProfile`),
  `assignedAgentId` (FK `Agent`), `parentTaskId` (nullable, self-FK),
  `allowedToolActions` (Json — list of `{ toolId, actionId }`),
  `allowedResourceSelectors` (Json — list of resource patterns, e.g.
  `{ toolId, pattern }`), `forbiddenActions` (Json, explicit denies that
  win over allows), `status` (enum: `PENDING | ACTIVE | EXPIRED |
REVOKED | COMPLETED`), `startsAt`, `expiresAt`, `maxExecutions`
  (nullable), `executionCount` (default 0), `riskCeiling` (int 0-100,
  default conservative), `createdAt`.
- `TaskDelegation`: `id`, `parentTaskId`, `childTaskId` — exists mainly
  to make the delegation chain queryable/auditable independent of the
  self-referencing `parentTaskId` FK; keep it thin.

Migration.

## OpenFGA authorization model

Design and commit an explicit `.fga`/JSON authorization model file under
`src/authorization/model/` (research OpenFGA's current modeling docs —
this is a real Zanzibar-style relationship model, not a rules engine;
model it properly rather than approximating). At minimum it must express:

- `tenant`, `user`, `agent`, `task`, `tool`, `tool_action`, `resource`
  as types.
- A task's grants are expressed as relationship tuples between the task
  (or a per-grant object) and specific `tool_action`/`resource` pairs —
  written when the task is created, not computed dynamically from JSON
  columns. The Postgres `allowedToolActions`/`allowedResourceSelectors`
  columns are the human/audit-readable record of intent; OpenFGA tuples
  are the actual enforcement substrate `AuthorizationService` checks
  against. Keep these in sync at write time (task creation/delegation),
  don't let them drift into two sources of truth for the same decision.
- An agent can only exercise a grant while it is the task's
  `assigned_agent` — permission flows through the task, never attached
  to the agent directly (Section 18's "agents start with effectively zero
  useful permanent authority").
- Write an OpenFGA model test suite (`.fga.yaml`, OpenFGA's own test
  format) covering: assigned agent can perform a granted action; a
  different agent cannot use another agent's task grant; an action not
  in the grant list is denied; an explicitly forbidden action is denied
  even if it would otherwise match an allow pattern.

## `AuthorizationService`

`POST /agent/v1/authorize` (mTLS-guarded, per Phase 4) accepting
`{ taskId, toolId, actionId, resource }`. Pipeline, fail-closed at every
step (Section 22 — if any check can't be evaluated trustworthily, DENY):

1. Resolve `Task`, confirm `assignedAgentId` matches the mTLS-authenticated
   agent.
2. Walk the **entire ancestor chain** (`parentTaskId` recursively) and
   confirm every ancestor task is `ACTIVE`/unexpired/under its execution
   limit — not just the immediate task. This is what makes revoking a
   parent immediately invalidate all descendants without needing cascade
   writes across a potentially large descendant tree (Section 20's
   revocation-invalidates-descendants requirement, implemented as a
   real-time check rather than an eventually-consistent cascade).
3. Confirm `now` is within `[startsAt, expiresAt]` and
   `executionCount < maxExecutions` (if set).
4. Check `forbiddenActions` — explicit deny short-circuits to DENY.
5. OpenFGA `check()` for the specific tool_action/resource against this
   task's grant tuples.
6. On ALLOW, increment `executionCount` atomically.

No policy engine, no risk score, no approval flow yet — those are Phase
6/8. This endpoint returns a bare `ALLOW`/`DENY` plus the reason it
failed (for step 2-4 failures, a specific reason; OpenFGA denials can be
a generic "not authorized" — don't leak the shape of the authorization
model to the caller).

## Delegation & subagents

`POST /agent/v1/tasks/:id/delegate` (mTLS-guarded, caller must be the
task's `assignedAgentId`): body describes the child task's desired
`allowedToolActions`/`allowedResourceSelectors` (a subset request) and a
slug for the new child agent. Server:

1. **Deterministic subset check**: every requested child grant must
   already be present in the parent task's _effective_ grants (which
   itself means the parent's own ancestor-chain-intersected grants —
   don't allow a parent whose own authority was already narrowed by an
   ancestor to hand out more than what actually still applies to it). If
   the request asks for anything not in that set, reject the whole
   delegation — never silently narrow it and partially succeed.
2. Create the child `Agent` (`PENDING_ENROLLMENT`, reusing Phase 4's
   model — this is not a new identity mechanism, delegation issues a
   fresh one-time enrollment token via the same `AgentEnrollmentToken`
   flow so the child agent gets its own independent certificate; the
   chain Human → Parent Task → Parent Agent → Child Task → Child Agent
   is reconstructable from `Task.parentTaskId` + `Task.assignedAgentId`
   - `Agent.createdBy` fields, don't invent a separate audit log for this
     yet — full audit chaining is Phase 9).
3. Create the child `Task` (`parentTaskId` set) with exactly the
   requested (now-verified-subset) grants, write its OpenFGA tuples.
4. Return the child task + enrollment token.

## Testing (mandatory — Section 80 invariants)

- Assigned agent performs a granted action → ALLOW.
- Assigned agent attempts an action outside task scope → DENY.
- A different (non-assigned) agent attempts to use the task → DENY.
- Delegation requesting a grant the parent doesn't hold → rejected, no
  child task/agent created (verify nothing partial was persisted).
- Delegation requesting a strict subset → succeeds; child agent enrolls
  (reuse Phase 4's SDK flow) and can perform only its narrower grant.
- **Privilege amplification attempt**: child task tries to have grants
  added after creation that exceed the original subset (e.g. directly
  attempting to authorize an action never granted to it, or a second
  delegation attempt trying to broaden scope) → DENY.
- **Revocation cascade**: revoke the parent task; a previously-successful
  child-task authorization now DENIES on retry, without any explicit
  cascade write to the child (proves the ancestor-walk enforcement).
- Expired task (`expiresAt` in the past) → DENY, even if the OpenFGA
  tuples still exist (proves expiry is enforced at the application layer,
  not assumed to be mirrored into OpenFGA).
- `maxExecutions` exhausted → DENY on the next attempt.
- OpenFGA unavailable (simulate by pointing at a wrong port/killing the
  container for the test) → the whole authorize call fails closed
  (DENY / 5xx-that-is-not-ALLOW), never silently permits (Section 80's
  "OpenFGA outage → fails closed" invariant).

## Docs

`docs/authorization-model.md` (Section 87) explaining the OpenFGA model,
the JSON-columns-vs-tuples sync approach, and the ancestor-chain
revocation mechanism. `docs/task-delegation.md` covering the subset
invariant and the enrollment-token-reuse delegation flow.

## Out of scope this phase

- Deterministic policy engine, risk scoring, approvals (Phase 6/8)
- Tool registry / actual tool execution (Phase 7)
- Kill switches as a first-class dedicated feature (this phase only gets
  task-level revoke; the five-scope kill-switch system is later)
- Full audit hash chain (Phase 9) — structured logs only this phase
