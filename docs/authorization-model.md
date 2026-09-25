# Authorization model (OpenFGA)

This is `manar-api`'s implementation of the OpenFGA-based half of Phase 5
(Tasks, Delegation & OpenFGA):
`docs/superpowers/specs/2026-08-18-phase5-tasks-openfga-design.md`. It
covers Sections 18-20 and 22: agents start with zero permanent authority
and receive only narrowly-scoped, expiring task authority; a child
task/agent can never exceed its parent's authority; every authorization
decision fails closed. See `docs/task-delegation.md` for the delegation
flow itself (creating child tasks/agents); this document covers the
authorization _model_ and the `/agent/v1/authorize` pipeline that checks
against it.

## Local infra: OpenFGA

`deploy/docker-compose.yml` adds `openfga` (`openfga/openfga:v1.18.3`)
using its Postgres storage engine — a new `openfga` database on the same
shared Postgres server every other local service uses, matching the
"nothing ephemeral" posture the rest of local infra already follows
(unlike, say, a quick-start in-memory datastore). Because Postgres has no
`CREATE DATABASE IF NOT EXISTS`, an `openfga-db-init` one-shot job creates
it idempotently before `openfga-migrate` (OpenFGA's own required schema
migration command — `openfga run` does not auto-migrate) runs, and the
`openfga` server only starts once that completes
(`depends_on: condition: service_completed_successfully`, mirroring the
official `openfga/openfga` `docker-compose.yaml`'s own sequencing). The
image ships no shell at all (a scratch-style container — `docker exec sh`
fails outright), so its healthcheck uses the bundled `grpc_health_probe`
binary directly rather than the `/dev/tcp` shell trick
Keycloak's/OpenFGA-adjacent healthchecks elsewhere in this file use.

## Store/model bootstrap: no separate init script

Unlike OpenBao's CA bootstrap (`deploy/openbao-init.mjs`, a separate,
manually-invoked, idempotency-guarded script — necessary there because
regenerating a CA is destructive), resolving-or-creating the OpenFGA store
and writing-or-reusing its authorization model happens automatically,
every time this process boots (`OpenFgaClientService.onModuleInit`,
`src/authorization/openfga-client.service.ts`):

1. If `OPENFGA_STORE_ID` is set, use it directly. Otherwise, list stores
   and find one named `OPENFGA_STORE_NAME` (default `manar`); create one
   if none exists.
2. If `OPENFGA_AUTHORIZATION_MODEL_ID` is set, use it directly. Otherwise,
   read the DSL file (`OPENFGA_MODEL_FILE_PATH`, default
   `src/authorization/model/manar.fga`), transform it to JSON via
   `@openfga/syntax-transformer`, and compare it against the store's
   latest model. If they match, reuse that model's ID; otherwise write a
   new model version (OpenFGA model versions are write-once and purely
   additive, so this never mutates or loses an old version — it just
   avoids churning `authorizationModelId` on every boot when the DSL
   hasn't actually changed, e.g. in local dev with hot reload).

This is a deliberate deviation from the "separate init script" pattern
Phase 4 established: there is no destructive-if-rerun hazard here the way
there is for CA generation, so there's no reason to make an operator run a
second command and copy a generated ID into `.env` by hand.
`OPENFGA_STORE_ID`/`OPENFGA_AUTHORIZATION_MODEL_ID` still exist as real,
optional config fields (the "existing typed-config pattern" the design
spec asks for) for a deployment that wants to pin a specific store/model
explicitly instead.

## The model: `src/authorization/model/manar.fga`

A real Zanzibar-style relationship model (OpenFGA schema 1.1), not a rules
engine approximating one:

```
type user

type tenant
  relations
    define member: [user]

type agent
  relations
    define tenant: [tenant]

type tool
  relations
    define tenant: [tenant]

type tool_action
  relations
    define tool: [tool]

type resource
  relations
    define tool: [tool]

type task
  relations
    define tenant: [tenant]
    define assigned_agent: [agent]

type grant
  relations
    define of_task: [task]
    define tool_action: [tool_action]
    define resource: [resource]
    define forbidden_agent: [agent]
    define can_use: (assigned_agent from of_task) but not forbidden_agent
```

### Permission flows through the task, never the agent

`grant#can_use` is computed as `assigned_agent from of_task` — "whoever is
`of_task`'s `assigned_agent`, right now" — rather than ever being a tuple
written directly against an agent. An agent that stops being a task's
`assigned_agent` (which never actually happens in this phase — task
assignment cannot be changed after creation — but the model doesn't special-case
that) loses `can_use` automatically, with no tuple to delete. This is the
literal implementation of Section 18: "agents start with effectively zero
useful permanent authority" — `Agent.capabilities` stays an unused empty
JSON object forever; the only authority an agent ever has flows through
whichever task it's currently assigned to.

### A `grant` is a synthetic per-triple object

A task's grants are the cross-join of its `allowedToolActions`
(`{ toolId, actionId }[]`) and `allowedResourceSelectors`
(`{ toolId, pattern }[]`), matched by `toolId` — see
`src/authorization/grant-triples.ts`'s `computeGrantSet`. One `grant`
object is written per resulting triple, with a deterministic ID:

```ts
grantObjectId(tenantId, taskId, toolId, actionId, resourcePattern);
//  = `grant:${sha256hex([tenantId, taskId, toolId, actionId, resourcePattern].join('|'))}`
```

Deterministic on purpose: `AuthorizationService` never needs to search for
"which grant applies here" — given the incoming `{ taskId, toolId,
actionId, resource }` from `POST /agent/v1/authorize`, it recomputes the
exact same ID the writer used and calls `check()` against it directly. No
`ListObjects`/`Expand` scan.

### Object identifiers avoid `:` inside the id portion

OpenFGA parses `type:id` on the _first_ colon, but (confirmed empirically
against a real local OpenFGA server while building this model) the `id`
portion itself must not contain a colon — `doc:tenant-1:file1` is rejected
as malformed; `doc:tenant-1_file1` is accepted. Every helper in
`src/authorization/openfga-object-id.util.ts` joins multi-part identifiers
with `_` for this reason (UUIDs already use `-`, so `_` can't collide).
`toolId`/`actionId` are validated to a safe slug-like charset
(`src/authorization/grant-triples.ts`'s `ToolActionSchema`) and used
verbatim for readability; `resource` patterns are arbitrary caller-supplied
text (URLs, file paths, ...) and are hashed into the object ID instead of
validated/escaped.

### Explicit denies win over allows — inside the model itself, not just app-side

`Task.forbiddenActions` (`{ toolId, actionId }[]`) is mirrored into OpenFGA
as `forbidden_agent` tuples on every matching `grant` object (crossed with
the same resource selectors the allow side uses), and `can_use`'s
definition is `(assigned_agent from of_task) but not forbidden_agent` — the
model's own exclusion operator enforces "forbidden wins" independently of
`AuthorizationService`'s own app-layer short-circuit (step 4 of the
pipeline, below). This is deliberate defense in depth: even if the
app-layer check were ever bypassed by a bug, OpenFGA's own `check()` would
still deny.

### Known limitation: no resource glob/prefix matching

`allowedResourceSelectors[].pattern` is either a literal resource
identifier or the sentinel `"*"` ("any resource for this tool action").
There is no glob/prefix matching (`files/*.txt`, `s3://bucket/**`, ...) —
that's real policy-engine territory (Phase 6/8's scope), not this phase's
relationship-authorization engine, and approximating it inside OpenFGA
would mean inventing pattern-matching logic OpenFGA itself doesn't have
rather than modeling relationships properly. `AuthorizationService`'s step
5 tries exactly two `check()` calls per request — the exact resource
string, and the `"*"` wildcard grant — and ALLOWs if either succeeds.

### Known limitation: OpenFGA is a single deployment-wide store, not per-tenant

Every tenant's tasks/agents/grants live in the _same_ OpenFGA store (see
`OPENFGA_STORE_NAME`), unlike Postgres's structural per-tenant database
isolation (`docs/tenant-isolation.md`). Every object ID is prefixed with
`tenantId` (a UUID) precisely to give this real, if softer, isolation —
two tenants' objects can never collide by construction, since two
different UUIDs can never produce the same prefixed ID — but this is
collision-avoidance via namespacing, not a hard boundary the way a
separate Postgres database is. A production deployment wanting a harder
boundary could run one OpenFGA store per tenant instead; this phase
doesn't, since nothing in the current threat model requires it and a
shared store is simpler to operate.

### Model test suite

`src/authorization/model/manar.fga.yaml` (OpenFGA's own YAML test format,
run via `pnpm fga:test` against the official `openfga/cli` Docker image)
covers the four mandatory scenarios:

1. The task's assigned agent can use a grant tied to its own task.
2. A different (non-assigned) agent cannot use that task's grant.
3. An action never granted to the task (no tuples for that grant object at
   all) denies by default — OpenFGA's closed-world assumption, not an
   explicit deny.
4. An explicitly forbidden action denies even though the same agent's
   task-assignment relationship is otherwise identical to a granted-action
   case — proves the model's own `but not` exclusion, independent of any
   app-layer short-circuit.

All 4 pass (`pnpm fga:test`).

## `AuthorizationService`: the 6-step pipeline

`POST /agent/v1/authorize` (mTLS-guarded, `src/authorization/authorize.controller.ts`)
accepts `{ taskId, toolId, actionId, resource }` and always responds
200/201 with `{ decision: 'ALLOW' }` or `{ decision: 'DENY', reason }` — a
DENY is a legitimate, expected policy-decision-point answer, never mapped
to an HTTP error status (that would leak _why_ through the status code on
top of the returned `reason`). `src/authorization/authorization.service.ts`
implements the pipeline exactly as designed, fail-closed at every step
(Section 22 — if a check can't be evaluated trustworthily, DENY):

1. Resolve the `Task`, confirm `assignedAgentId` matches the
   mTLS-authenticated agent (`AgentMtlsGuard`'s `AgentContext`).
2. Walk the **entire ancestor chain** (`TasksService.getAncestorChain`,
   following `parentTaskId` recursively, bounded at 64 hops — a cyclic
   chain fails closed rather than looping forever) and confirm every
   ancestor is `ACTIVE`, within its own `[startsAt, expiresAt]` window, and
   under its own `maxExecutions`.
3. Confirm the task itself passes those same three checks.

   Steps 2-3 together are `TasksService.evaluateFullLiveness` — this is
   Section 20's real-time revocation-cascade mechanism: **revoking a
   parent task immediately denies every descendant's very next
   `/authorize` call, with no cascade write ever touching the descendant.**
   Nothing about a descendant Task row changes when an ancestor is
   revoked; the ancestor walk _is_ the enforcement.

4. Check `forbiddenActions` — an explicit deny short-circuits to DENY
   before OpenFGA is ever consulted.
5. `OpenFgaClientService.check()` against the exact-resource and `"*"`
   wildcard grant objects (see above). A transport/server failure here
   (OpenFGA down, wrong port, network partition) is caught and treated as
   DENY (`authorization_backend_unavailable`) — **never** as ALLOW.
6. On ALLOW, atomically increment `executionCount` — a single conditional
   `UPDATE ... WHERE executionCount < maxExecutions` when a limit is set
   (the same race-closing pattern `AgentsService.enroll` uses for
   single-use enrollment tokens), so a request that loses a race against a
   concurrent one exhausting the limit gets converted into a DENY instead
   of a stale ALLOW.

Steps 1-4's DENY reasons are specific (`not_assigned_agent`,
`ancestor_task_status_revoked`, `task_outside_time_window`,
`forbidden_action`, ...) — deterministic app-layer state, safe to expose.
Step 5's DENY is deliberately generic (`not_authorized`) so a caller can
never learn the shape of the authorization model from a failed check.

## Postgres JSON columns vs. OpenFGA tuples: two angles, one decision

`Task.allowedToolActions`/`allowedResourceSelectors`/`forbiddenActions`
(Postgres JSONB) are the human/audit-readable record of what was granted —
queryable/diffable the ordinary way, no OpenFGA client needed to answer
"what was this task allowed to do." OpenFGA's tuples are the actual
enforcement substrate `AuthorizationService` checks against. Both are
written from the _same_ input, in the _same_ call
(`TasksService.createTask` → `TaskGrantSyncService.writeTaskGrants`,
immediately after the Postgres row commits) — never two independent
sources of truth that could drift apart. `TaskGrantSyncService` writes a
straightforward, unfiltered 1:1 tuple-ization of all three JSON columns
(not a pre-filtered "effective" subset), so the "explicit deny wins" logic
lives identically in both places: `AuthorizationService`'s step 4
short-circuit, and the model's own `but not forbidden_agent` exclusion.

If the OpenFGA write fails after the Postgres row is already committed,
the task is left `ACTIVE` with no enforceable grants — every
`/authorize` check for it will DENY (no `grant` tuples exist to `check()`
against), fail-closed, never silently permissive. Consistent with this
codebase's established "no automatic rollback, fail loud" stance elsewhere
(`TenantDatabaseManager.provisionTenant`).

## Out of scope this phase

- Deterministic policy engine, risk scoring, approvals (Phase 6/8).
- Tool registry / actual tool execution (Phase 7) — `toolId`/`actionId`
  are opaque, caller-supplied strings this phase, validated only for shape
  (a safe slug-like charset), never resolved against a real tool catalog.
- Resource glob/prefix pattern matching (see "known limitation" above).
- Per-tenant OpenFGA stores (see "known limitation" above).
- Kill switches as a first-class dedicated feature — this phase only gets
  task-level revoke (`docs/task-delegation.md`); the five-scope
  kill-switch system is a later phase.
- Full audit hash chain (Phase 9) — structured logs only.
