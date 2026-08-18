# Tamper-evident audit chain & Kafka event backbone

This is `manar-api`'s implementation of Phase 9a (Tamper-Evident Audit
Chain & Kafka Event Backbone):
`docs/superpowers/specs/2026-08-19-phase9a-audit-chain-kafka-design.md`,
Sections 46-47 and 29. This phase is mostly **retrofit** — instrumenting
call sites that already existed in Phases 4-8 with real, cryptographically
hash-chained `AuditEvent` recording, rather than new business logic. See
`docs/agent-identity.md`, `docs/task-delegation.md`,
`docs/authorization-model.md`, `docs/policy-model.md`, `docs/tool-gateway.md`,
and `docs/approvals.md` for what each retrofitted decision point actually
does — this document covers only the audit chain itself and how it's wired
into them.

## Local infra: Kafka

`deploy/docker-compose.yml` adds `kafka` (`apache/kafka:4.3.1`, the
official ASF-maintained image), a single-node, combined broker+controller
KRaft cluster — Kafka 4.x has removed ZooKeeper support entirely
(KIP-500/KIP-833), so KRaft is not a preference here, it's the only mode
the current image supports. Two listeners: `PLAINTEXT` (`kafka:9092`, for
any future client running _inside_ the compose network — nothing today
uses this) and `PLAINTEXT_HOST` (`localhost:29092`, host port `29092`
— what every process in this repo actually connects through, since the
HTTP apps, the worker process, and every test suite all run on the host).
No separate cluster-ID bootstrap step: the image generates and persists
one itself on first boot for a single-node cluster (only a genuine
multi-node cluster needs one generated and shared ahead of time).

One topic, `manar.audit-events` (`KAFKA_AUDIT_TOPIC`, matching
`AUDIT_EVENTS_TOPIC` in `src/audit/domain-event-envelope.ts`) — not 30
topics for 30 event types. A consumer filters on the envelope's own
`eventType` field instead; see "Event envelope" below. `KafkaPublisherService`
creates this topic automatically on first connect (`admin.createTopics`,
a documented no-op if it already exists), the same "resolve-or-create,
no separate init job" posture `OpenFgaClientService.onModuleInit` already
establishes for the OpenFGA store/model (`docs/authorization-model.md`) —
there's no destructive-if-rerun hazard here the way there is for OpenBao's
CA bootstrap, so there's no reason to make an operator run a second
command.

## Node.js Kafka client: `@confluentinc/kafka-javascript`

`kafkajs` — the historically dominant Node Kafka client — has had no npm
release since February 2023 and is effectively unmaintained. This phase
uses `@confluentinc/kafka-javascript` instead: a librdkafka-backed client
published and supported by Confluent, with first-class TypeScript types
shipped in the package itself, and a `KafkaJS`-compatible API surface
(`kafka.producer()`/`.send()`, `kafka.consumer()`/`.subscribe()`/`.run()`)
that both `KafkaPublisherService` and the test suites use directly. Its
`consumer()` config shape differs from vanilla `kafkajs` in one place worth
knowing: `fromBeginning` is a `consumer({ kafkaJS: { fromBeginning } })`
constructor option, not a `.subscribe()` option — see
`test/audit-kafka-idempotency.e2e-spec.ts`.

## Event envelope (Section 29)

```ts
interface DomainEventEnvelope {
  eventId: string;
  eventType: string;
  eventVersion: number;
  tenantId: string;
  timestamp: string;
  correlationId: string;
  actor: { type: 'human' | 'agent' | 'system'; id: string };
  data: unknown;
}
```

(`src/audit/domain-event-envelope.ts`). `eventId` is the same value as the
`AuditEvent.id` it was published for. `eventVersion` is always `1` this
phase (no prior version exists yet to migrate from) — a schema-version
escape hatch for a future breaking change to one `eventType`'s `data`
shape. Published keyed by `tenantId` (not `eventId`) so Kafka's own
partition-ordering guarantee gives a consumer a per-tenant ordered stream.

**Consumers must be idempotent** — Kafka delivery is at-least-once, never
exactly-once. A future consumer (Phase 9b's OpenSearch indexer) must
upsert by `eventId`, never blindly append;
`test/audit-kafka-idempotency.e2e-spec.ts` proves this contract against
the real broker with a small test consumer, since Phase 9b's real indexer
doesn't exist yet.

## Data model (tenant DB)

`prisma/tenant.prisma`, migration `20260818223038_add_audit_chain`:

- **`AuditEvent`**: `id`, `sequence` (a plain autoincrement, purely for
  cheap "walk the chain in recorded order" ordering — it plays no role in
  the hash chain itself, which is entirely defined by `previousHash`/
  `eventHash` linkage), `eventType`, `correlationId`, `actor` (Json —
  `{ type, id }`), `timestamp` (captured once in application code, before
  hashing — never a DB default, which would make the hash unreproducible
  from the row's own stored fields), `data` (Json — the actual decision
  inputs, per Section 46), `previousHash` (nullable — `null` only for a
  tenant's very first event), `eventHash`. **Append-only**: there is no
  update/delete endpoint or code path for this model anywhere in the
  application — retention deletion (Phase 9b) is the one future exception,
  and will go through a dedicated, auditable workflow, never ad hoc code.
- **`AuditChainState`**: a singleton row (`id = "singleton"`, a fixed
  known ID — a tenant database only ever has exactly one chain, Phase 2's
  per-tenant isolation already gives this row tenant scoping for free),
  `latestEventId`, `latestEventHash`, `eventCount`, `updatedAt`. Exists so
  appending the next event never requires scanning the whole table for its
  tail.

## Canonical serialization — `src/audit/canonical-json.ts`

`eventHash` must be deterministic regardless of the key insertion order
any particular call site happened to construct its `data`/`actor` object
in. Plain `JSON.stringify` preserves insertion order for string keys —
relying on that would make the hash chain a hidden dependency on _how_ an
event object happens to be built today; a future refactor that reorders
how, say, `AuthorizationService` constructs its `data` payload would then
silently change every new event's hash relative to what an external
verifier expects, with no compiler error anywhere near that refactor.

`canonicalize(value)` recursively rebuilds `value` with every plain
object's keys sorted lexicographically (at every depth), while **never**
reordering array elements — array order is semantically significant
elsewhere in this codebase's event data (e.g. first-match-wins policy rule
lists, `docs/policy-model.md`), unlike object key order, which never is.
`Date` instances normalize to their ISO-8601 string form explicitly.
`src/audit/canonical-json.spec.ts` asserts this directly: differently
key-ordered but structurally identical objects (including nested inside
arrays, at multiple depths) canonicalize to byte-identical output, and
array order is never touched.

`computeEventHash` (`src/audit/audit-hash.ts`) is the one place
`eventHash = sha256(canonicalize({ id, eventType, correlationId, actor,
timestamp, data, previousHash }))` is ever computed — shared identically
by `AuditService.record` (computing a _new_ event's hash) and
`verifyAuditChain` (recomputing every _stored_ event's hash), so the two
can never drift apart from each other.

## `AuditService` (`src/audit/audit.service.ts`)

`record(tenantClient, tenantId, { eventType, actor, data, correlationId? })`:
a transactional read-modify-write against `AuditChainState`.

1. Upserts the singleton `AuditChainState` row into existence (no-op after
   the first call for a tenant).
2. Locks it with `SELECT ... FOR UPDATE`, inside the same transaction that
   will insert the new `AuditEvent` and advance the chain tail — a real
   Postgres row lock, held for the duration of the transaction. This is
   what actually prevents two concurrent `record` calls — even across
   separate API replicas, which an in-memory mutex could never coordinate
   — from forking the chain by both computing the same `previousHash`: the
   second caller's `FOR UPDATE` blocks until the first transaction
   commits, so it always reads the first call's freshly-written
   `latestEventHash` as its own `previousHash`.
3. Computes `eventHash`, inserts the `AuditEvent`, updates
   `AuditChainState.latestEventId`/`latestEventHash`/`eventCount` — all
   inside the one transaction, so a crash between any two of those steps
   leaves the chain exactly as it was before the call started, never
   partially advanced.
4. **After** that transaction has already committed, publishes the same
   content as a `DomainEventEnvelope` to Kafka — **not awaited** by the
   caller. `KafkaPublisherService.publish` itself never throws (retried a
   bounded number of times with a short fixed delay, then logs loudly and
   gives up); `record` doesn't await it at all, specifically so a Kafka
   outage adds zero latency to hot call sites like
   `AuthorizationService.authorize`. The `AuditEvent` row is the
   authoritative record; Kafka is a downstream notification a future
   consumer reads, never something this method's own success depends on.
   `KafkaPublisherService.onModuleInit` likewise never lets a Kafka outage
   fail the whole Nest application's _startup_ — a connection failure
   there is caught and logged, with every subsequent `publish()` call
   retrying the connection lazily on its own.

`recordSafely(...)` wraps `record` to log-and-swallow any failure instead
of propagating it — **every retrofit call site in this codebase uses this
method, not `record` directly** (see "Retrofit points" below). This
phase's retrofit work must never change any existing decision's outcome or
response shape; a rare Postgres failure specific to the audit tables must
not therefore also fail the actual authorization decision / task creation
/ tool invocation the call is merely recording alongside. `record` itself
stays available (and does propagate failures) for `verifyAuditChain`'s own
test suite and any caller that specifically wants to observe an
audit-write failure.

### `verifyAuditChain`

`verifyAuditChain(tenantClient): Promise<{ valid: true } | { valid: false; brokenAt: string }>`
walks every `AuditEvent` in recorded order (`sequence`), and for each one:

1. Confirms its `previousHash` matches the _previous_ event's `eventHash`
   (or `null`, for the first event) — a mismatch means a row was removed,
   reordered, or had its position in the chain altered.
2. Recomputes `eventHash` from the row's own stored content and confirms
   it matches what's stored — a mismatch means this row's content (or its
   `eventHash` itself) was tampered with directly.

Either failure returns `{ valid: false, brokenAt: <the AuditEvent.id where
verification first failed> }` — not just "invalid" (Section 47's mandatory
"modify an old event, prove verification fails _and correctly reports
where_" requirement). Also confirms the chain's tail matches
`AuditChainState` itself, reporting `brokenAt: 'audit_chain_state'` for a
mismatch there.

Exposed via `GET /audit/verify` (`src/audit/audit.controller.ts`),
JWT-guarded to `AUDITOR`/`SECURITY_ADMIN`/`TENANT_OWNER` — `AUDITOR`'s
first real consumer anywhere in this codebase (the role has existed since
Phase 3, but no endpoint had gated on it until now).

## Retrofit points

Every call listed here uses `AuditService.recordSafely` — additive
instrumentation alongside existing, unchanged logic, never a parallel
decision path:

| Event type(s)                                                                       | Where                                                                                        | Actor                                                                                                                                                                                             |
| ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `agent.enrolled` / `agent.enrollment_failed`                                        | `AgentsService.enroll`                                                                       | the enrolling agent (or `system:unauthenticated` if no agent could be resolved)                                                                                                                   |
| `agent.revoked`                                                                     | `AgentsService.revokeAgent`                                                                  | the human who revoked it                                                                                                                                                                          |
| `task.created`                                                                      | `TasksService.createTask`                                                                    | the human requester (root task), or the delegating agent (`DelegationService` passes this explicitly — a child task's `requesterId` is deliberately the _root_ requester, never the actual actor) |
| `task.revoked`                                                                      | `TasksService.revokeTask`                                                                    | the human who revoked it                                                                                                                                                                          |
| `task.delegated`                                                                    | `DelegationService.delegate`                                                                 | the delegating agent                                                                                                                                                                              |
| `authorization.allowed` / `authorization.denied` / `authorization.pending_approval` | `AuthorizationService.authorize` — every return statement in the 6-step pipeline             | the authenticated agent                                                                                                                                                                           |
| `approval.requested`                                                                | `ToolInvokeController.startApproval`                                                         | the requesting agent                                                                                                                                                                              |
| `approval.approved` / `approval.denied`                                             | `GrantService.finalizeDecision`                                                              | the approving/denying human                                                                                                                                                                       |
| `approval.grant_issued`                                                             | `GrantService.reevaluateAndIssueGrant` (runs inside the Temporal worker process — see below) | `system:approval-workflow` — this is the automated re-evaluation Activity's own decision, distinct from the human's raw `approval.approved` decision                                              |
| `tool.invocation.started` / `.completed` / `.failed`                                | `CredentialBrokerService.invoke`                                                             | the invoking agent                                                                                                                                                                                |
| `policy.published`                                                                  | `PolicyService.publishVersion`                                                               | the publishing human                                                                                                                                                                              |

### `AuthorizationService.authorize`: "why", not just the outcome

Every branch's `data` carries enough to reconstruct _why_ the decision
happened (Section 46) — not just the reason string already returned to
the caller: the matched policy rule and `PolicyVersion` id, the
`RiskEngine` score and its `reasonCodes`, the raw OpenFGA `check()`
booleans (exact-resource and wildcard grant), and the task's own
`riskCeiling`, in addition to `taskId`/`toolId`/`actionId`/`resource`/
`reason`. None of the pipeline's own steps, reason strings, or response
shape changed — the audit call is purely additive at each existing
`return` statement.

### Tool invocation: credential secrecy is a hard rule

`CredentialBrokerService.invoke`'s `data` never includes the resolved
credential — this is the one absolute rule this phase's retrofit work
enforces, not merely documents: `test/audit-retrofit.e2e-spec.ts` greps
the _actual_ stored `AuditEvent` rows (every `tool.invocation.*` event
from a real invocation, not just the ones a given assertion happens to
check) for the real credential value used in that test, over both `data`
and the full serialized row. `data` also never carries the raw request
`params` or a raw tool response body — the same conservative posture the
existing operational `ToolInvocation` row (Phase 7b) already takes
(`resource`/`status`/`errorMessage` are shape/summary only).

### The Temporal worker process needs `AuditService` too

`approval.approved`/`approval.denied`/`approval.grant_issued` are recorded
from inside `GrantService.finalizeDecision`, which runs as a Temporal
Activity — in the _separate_ worker process (`src/worker.main.ts`), not
either Fastify HTTP process. `AuditModule` is `@Global()` and imported
into all three application root modules
(`AppModule`/`AgentMtlsAppModule`/`WorkerAppModule`) for exactly this
reason — each `NestFactory.create()`/`createApplicationContext()` call
gets its own DI container (and therefore its own `KafkaPublisherService`
producer connection), the same "global only means global within one
application's module graph" caveat every other `@Global()` module in this
codebase already documents. The worker process never imports
`LoggingModule`, so `getCorrelationId()`'s `AsyncLocalStorage` context is
never populated there — `AuditService.record` falls back to a freshly
generated UUID for `correlationId` in that case.

## Testing

`src/audit/canonical-json.spec.ts` / `src/audit/audit-hash.spec.ts`: unit
tests for determinism (key-order independence, array-order preservation,
nested structures) and the exact `sha256(canonicalize(...))` formula.

`test/audit-chain.e2e-spec.ts` (real Postgres, no Keycloak/mTLS/Temporal
needed):

- A chain of 10 events verifies successfully; `previousHash` linkage is
  correct end to end.
- 20 concurrent `AuditService.record` calls against the same tenant never
  produce two events sharing a `previousHash` (no fork) — the resulting
  chain stays linear and verifies, and exactly one event has
  `previousHash === null`.
- Tampering a stored `AuditEvent.data` directly in the database, then
  calling `verifyAuditChain`, fails and reports the exact tampered
  event's id.
- Tampering a stored `AuditEvent.eventHash` directly does the same.

`test/audit-retrofit.e2e-spec.ts` (real Postgres/Keycloak/OpenBao/OpenFGA/
Temporal, both Nest apps + an in-process worker — mirroring
`test/approvals.e2e-spec.ts`'s setup): every retrofit point above actually
produces the right `AuditEvent`, with real data, when exercised via its
real API path (agent enrollment/revocation, task create/revoke/delegate,
`/agent/v1/authorize` ALLOW/DENY, the full tool-invoke → `PENDING_APPROVAL`
→ decide APPROVE/DENY → grant-issued flow, tool invocation success/failure
plus the credential-secrecy grep, policy publish) — plus `GET /audit/verify`
role-gating (reachable with `AUDITOR` alone, rejected for a caller with
none of the three roles).

`test/audit-kafka-idempotency.e2e-spec.ts`: publishes the same `eventId`
twice against the real local Kafka broker; a small test consumer that
upserts a `Map` keyed by `eventId` ends up with exactly one record, even
though both raw messages were actually delivered.

Phase 4-8's existing e2e suites (`test/agent-identity.e2e-spec.ts`,
`test/task-delegation.e2e-spec.ts`, `test/policy-risk.e2e-spec.ts`,
`test/tool-gateway.e2e-spec.ts`, `test/tool-gateway-demo-integration.e2e-spec.ts`,
`test/approvals.e2e-spec.ts`) were re-run and pass unmodified in behavior —
this phase only adds audit-recording calls alongside existing logic; the
only non-audit-module code changes are the same kind of additive
constructor/method-parameter changes earlier phases have already made once
each (e.g. `RiskEngine` gaining a `ToolRegistryService` parameter in Phase
7b) to thread `tenantId`/`actor` through to the new `AuditService` calls.

## Out of scope this phase

- OpenSearch indexing, OCSF mapping, SSE live feed, evidence export,
  retention/deletion (all Phase 9b — this phase produces what those
  consume).
- Webhooks (a later phase).
