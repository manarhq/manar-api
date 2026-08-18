# Task delegation

This is `manar-api`'s implementation of the delegation half of Phase 5
(Tasks, Delegation & OpenFGA):
`docs/superpowers/specs/2026-08-18-phase5-tasks-openfga-design.md`. See
`docs/authorization-model.md` for the OpenFGA relationship model and the
`/agent/v1/authorize` pipeline this flow's grants are checked against.

## Data model: `Task`

`prisma/tenant.prisma`'s `Task` model (migration
`20260818194201_add_task_and_delegation`) is a narrowly-scoped, expiring
grant of authority to exactly one agent — the _only_ way an agent ever
does anything (Section 18: `Agent.capabilities` stays an unused empty
object forever). Key fields: `requesterId` (the human who ultimately
requested it — see "root requester" below), `assignedAgentId`,
`parentTaskId` (self-FK, null for a root task), the three grant JSON
columns (`allowedToolActions`/`allowedResourceSelectors`/
`forbiddenActions` — see `docs/authorization-model.md`), `status`,
`startsAt`/`expiresAt`/`maxExecutions`/`executionCount`, `riskCeiling`.

`status` defaults straight to `ACTIVE` at creation — there's no approval
step yet (Phase 6/8), so `PENDING` is never actually set by anything this
phase (kept in the enum now, unused, the same way `AgentStatus.KILLED` was
kept unused ahead of its own phase — avoids a destructive migration later).
`EXPIRED`/`COMPLETED` are likewise never set by any code this phase: expiry
is enforced by comparing `expiresAt` against `now` at authorization time,
never by a background job flipping status — this is deliberate (see the
"expired task denies even though its OpenFGA tuples still exist" test in
`docs/authorization-model.md`'s pipeline description). `REVOKED` is the one
status this phase's code actually sets.

`TaskDelegation` exists alongside `parentTaskId` purely to make the
delegation chain queryable/auditable as a first-class row without walking
the self-FK — kept thin per the design spec. `AuthorizationService`'s
ancestor walk (the actual enforcement mechanism) never consults it; it
walks `parentTaskId` directly.

## The human-facing root: `POST /tasks`

The design spec only names the agent-facing delegation endpoint
explicitly — but `Task.requesterId` is a required `UserProfile` FK, and
every delegation chain has to start somewhere: a _root_ task has no parent
to delegate from, so a human has to create it.
`src/tasks/tasks.controller.ts` adds `POST /tasks` (and
`POST /tasks/:id/revoke`), gated the same way `AgentsController` is
(`JwtAuthGuard`+`RolesGuard`, `SECURITY_ADMIN`/`TENANT_OWNER`/
`AI_GOVERNANCE_MANAGER` — tasking an agent is exactly as security-relevant
as creating one). This is a design decision the spec didn't fully pin down,
not scope creep: without it there is no way to ever populate the first
task a delegation chain descends from.

## `POST /agent/v1/tasks/:id/delegate`

mTLS-guarded (`src/delegation/`), the caller must be `:id`'s
`assignedAgentId`. `DelegationService.delegate`:

1. **Caller check**: the mTLS-authenticated agent must be the task's
   `assignedAgentId` — 403 otherwise.
2. **Liveness check**: the parent task (and _its_ entire ancestor chain)
   must be fully live right now (`TasksService.evaluateFullLiveness` — the
   same check `AuthorizationService` runs). This is slightly stricter than
   the bare letter of the design spec, which only names the grant-subset
   check below, but is clearly within its spirit: Section 20's
   non-amplification invariant would be meaningless if a revoked or
   expired task could still mint fresh sub-tasks. 409 otherwise.
3. **Deterministic subset check** (the spec's actual step 1): every
   requested child grant — the cross-join of the request's own
   `allowedToolActions`/`allowedResourceSelectors`, minus its own
   `forbiddenActions` (`computeGrantSet`) — must already be a member of
   the parent task's **effective** grant set
   (`TasksService.getEffectiveGrantSet`): the parent's own grant set
   intersected with every one of _its_ ancestors' own grant sets, all the
   way to the root. A parent whose own authority was already narrowed by
   an ancestor can never hand out more than what actually still applies to
   it. If anything requested isn't in that set, the **entire** delegation
   is rejected (403) — nothing is created. This check runs entirely before
   any write (no agent, no task, no OpenFGA tuple), so a rejected
   delegation is verifiably all-or-nothing, not a partial success silently
   narrowed down.
4. **Child agent**: `AgentsService.createAgent` (Phase 4, unchanged) — a
   new `Agent` row in `PENDING_ENROLLMENT`, plus
   `AgentsService.createEnrollmentToken` — a fresh, single-use enrollment
   token via the _same_ `AgentEnrollmentToken` flow a human-created agent
   uses. Delegation is not a new identity mechanism.
5. **Child task**: `TasksService.createTask` with `parentTaskId` set to the
   exact (now-verified-subset) requested grants, which also writes its
   OpenFGA tuples (`TaskGrantSyncService`) and the `TaskDelegation` row.
   `expiresAt` is clamped to the parent's own `expiresAt` if the request
   asked for later (or omitted it) — pure hygiene, not a security boundary
   in itself, since `AuthorizationService`'s ancestor walk would deny a
   too-long-lived child regardless once the parent expires.
6. Returns `{ childTask, childAgent, enrollmentToken }`.

### Root requester: who does a delegated task/agent belong to?

Both the child `Task.requesterId` and the child `Agent.createdBy` resolve
to the **root** task's original human requester
(`TasksService.resolveRootRequesterId`, walking `parentTaskId` to the top)
— never the delegating agent, which has no `UserProfile` row to point
either FK at. This is what keeps the chain **Human → Task → Agent → Task →
Agent → ...** fully reconstructable purely from `Task.parentTaskId` +
`Task.assignedAgentId` + `Agent.createdBy`, exactly as the design spec
describes, without inventing a separate audit log for delegation (full
audit hash-chaining is Phase 9's scope — this phase is structured logs
only).

## SDK: `ManarAgent.authorize()` / `.delegateTask()`

`packages/sdk-node` (still inside this one repo — see the Phase 5
constraints) adds two mTLS-authenticated calls to `ManarAgent`, built on a
new `mtlsRequestJson` helper (`node:https`-based — Node's global `fetch`
doesn't accept a plain client-certificate option the way `https.request`
does):

```ts
const manar = new ManarAgent({ endpoint, mtlsEndpoint, identityStore });
await manar.enroll(enrollmentToken); // Phase 4, unchanged

const decision = await manar.authorize({ taskId, toolId, actionId, resource });
// { decision: 'ALLOW' } | { decision: 'DENY', reason }

const { childTask, childAgent, enrollmentToken } = await manar.delegateTask(
  taskId,
  {
    childAgentSlug: 'sub-agent',
    name: 'Delegated subtask',
    allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
    allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
  },
);

// The child agent enrolls independently, exactly like any other agent:
const childManar = new ManarAgent({
  endpoint,
  mtlsEndpoint,
  identityStore: childIdentityStore,
});
await childManar.enroll(enrollmentToken.token);
```

`authorize()` never throws for a DENY — a DENY is a legitimate, expected
answer, not a transport error, mirroring `AuthorizeController`'s own
contract. `delegateTask()` throws (with the server's own message) if the
delegation is rejected for any reason (not the assigned agent, task not
live, requested grants exceed effective authority, duplicate agent slug).

## Testing

`test/task-delegation.e2e-spec.ts` runs every mandatory scenario from the
design spec's "Testing" section against real Postgres, Keycloak, OpenBao,
and OpenFGA (`pnpm infra:up`), using the real SDK for every agent-side
call — no mocking the authorization decision path:

- Assigned agent performs a granted action → ALLOW.
- Assigned agent attempts an out-of-scope action → DENY.
- A different (non-assigned) agent attempts to use the task → DENY.
- Delegation requesting a grant the parent doesn't hold → rejected (403),
  and neither a child `Agent` nor a child `Task` row exists afterward
  (queried directly against the real tenant database) — verifying nothing
  partial was persisted, not just that the HTTP call returned an error.
- Delegation requesting a strict subset → succeeds; the child agent
  enrolls via the real SDK flow and can perform only its narrower grant
  (an action the parent could do but the child wasn't granted → DENY).
- **Privilege amplification**: (a) the child task directly attempts to
  authorize an action it was never granted → DENY; (b) the child agent
  attempts a _second_ delegation trying to broaden scope beyond what it
  itself effectively holds → rejected, for the same subset-check reason as
  above, proving the non-amplification invariant holds transitively at any
  delegation depth, not just one level.
- **Revocation cascade**: a child task's authorization succeeds once, the
  _parent_ task is revoked (`POST /tasks/:id/revoke`), and the exact same
  child authorization request — retried with no change to the child task
  itself — now DENIES, with an assertion that no cascade write ever
  touched the child `Task` row (its `status` is still read back as
  `ACTIVE`). This is what actually proves the ancestor-walk enforcement
  works, not merely that a cascade update was written somewhere.
- Expired task (`expiresAt` backdated directly in Postgres) → DENY, even
  though its OpenFGA tuples still exist untouched — proving expiry is
  enforced at the application layer, never assumed to be mirrored into
  OpenFGA.
- `maxExecutions` exhausted (a task created with `maxExecutions: 1`,
  authorized once successfully, then retried) → DENY on the next attempt.
- **OpenFGA outage**: the real OpenFGA container is stopped mid-test (not
  simulated), and a previously-working authorize call against the exact
  same task/grant now fails closed (DENY, never ALLOW, never an unhandled
  exception) — then the container is restarted and the same call succeeds
  again, confirming this wasn't a permanent break.

## Out of scope this phase

- Deterministic policy engine, risk scoring, approvals (Phase 6/8).
- Tool registry / actual tool execution (Phase 7).
- Kill switches as a first-class dedicated feature (task-level revoke
  only this phase — the five-scope kill-switch system is later).
- Full audit hash chain (Phase 9) — structured logs only.
