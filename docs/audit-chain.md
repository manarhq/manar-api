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

# OpenSearch indexing, live SSE, evidence export, and retention

The rest of Phase 9b — folded into this document rather than four
separate files, since all four build directly on Phase 9a's audit chain
(`docs/audit-chain.md`) and share infrastructure.

## OpenSearch indexing (Section 45)

`AuditIndexerService` (`src/audit/opensearch/audit-indexer.service.ts`) is
a Kafka consumer on Phase 9a's `manar.audit-events` topic. For every
message, it upserts the event into OpenSearch by `eventId`
(`OpenSearchIndexService.upsertAuditEvent`, `src/audit/opensearch/opensearch-client.service.ts`)
— OpenSearch's Index API with an explicit `id` always _replaces_ any
existing document at that id, so Kafka's at-least-once redelivery never
double-indexes. **Postgres remains authoritative** — the index is a
queryable projection, never a second source of truth.

A single, tenant-tagged index (`OPENSEARCH_AUDIT_INDEX`, default
`manar-audit-events`) rather than one index per tenant, for MVP
simplicity — every document carries `tenantId`. `data`/`actor` are mapped
`enabled: false` (stored, not indexed) to avoid dynamic-mapping conflicts
across ~15 structurally-different `eventType`s sharing one index — see
that service's own doc comment.

### Consumer group id and `fromBeginning`

`AuditIndexerService` uses a fresh random Kafka consumer group id
(`manar-audit-indexer-<uuid>`) every process boot, not a fixed name —
avoids every concurrently-running test file's own `AppModule` instance
competing for the topic's single partition under one shared group id.

`fromBeginning: false`: a fresh group starts from the topic's _current_
end, never replaying full history. Historical backfill is deliberately
`pnpm manar audit:reindex`'s job (reading straight from Postgres, not
Kafka) — the live consumer's job is only to keep the index current going
forward. This also keeps a fresh group's catch-up time bounded regardless
of how much history the topic has accumulated over the deployment's
lifetime.

### Disaster recovery: `pnpm manar audit:reindex --tenant <id>`

`AuditReindexService` (`src/audit/opensearch/audit-reindex.service.ts`)
reads every `AuditEvent` for one tenant straight from Postgres (paginated
by `sequence`) and upserts each into OpenSearch — the real
disaster-recovery path if the index is ever lost or corrupted, never
reading from Kafka (a from-scratch rebuild must not depend on Kafka
retaining however much history has passed). `src/cli/commands/audit-reindex.command.ts`
is a thin `nest-commander` wrapper around it (Phase 2's CLI convention —
see `src/cli/commands/tenant-create.command.ts`).

## Live SSE (Section 62)

`GET /events/live` (JWT-guarded, tenant-scoped, no role restriction —
unlike `/audit/verify`/`/evidence/export`, a live activity feed is
reasonable for any authenticated tenant user to watch). Implemented as a
Server-Sent Events stream (`src/audit/live/live-events.controller.ts`).

**Publishing side**: rather than publish directly from
`AuditService.record`'s hot path, `AuditIndexerService` (the same Kafka
consumer that indexes into OpenSearch) also publishes every consumed
envelope to Redis (`RedisPubSubService.publish`,
`src/audit/live/redis-pubsub.service.ts`), on a per-tenant channel
(`manar:audit-live:<tenantId>`). This keeps `AuditService.record` free of
any new dependency on Redis's availability/latency, consistent with
Phase 9a's "a Kafka outage adds zero latency to hot call sites" posture
for `KafkaPublisherService` — the live feed is downstream of the same
already-fire-and-forget Kafka publish, one hop further.

**Subscribing side**: `GET /events/live` subscribes to its caller's
tenant channel for the connection's lifetime
(`RedisPubSubService.subscribeTenant`, a fresh dedicated Redis connection
per open SSE connection — `node-redis`'s own documented pub/sub contract:
a subscribed connection can't run other commands) and streams each
message as an `audit-event` SSE frame. Unsubscribes and disconnects the
instant the client closes the connection.

Redis here is fanout-only, never a durable store: a client that
reconnects after a dropped SSE connection just resumes seeing new events —
Postgres/OpenSearch remain the durable record for anything missed.

## Evidence export (Section 49)

`POST /evidence/export` (JWT-guarded, `AUDITOR`/`SECURITY_ADMIN`/
`TENANT_OWNER`) — `src/evidence/`. Accepts a filter (`since`/`until`
time window and/or `agentId`/`taskId`/`correlationId`; at least one
required) and returns a signed JSON bundle
(`EvidenceExportService.export`, `src/evidence/evidence-export.service.ts`).

**Filtering**: `since`/`until`/`correlationId` are real `AuditEvent`
columns. `agentId`/`taskId` aren't columns (they live inside the
heterogeneous per-`eventType` `data`/`actor` JSON) — the service
post-filters a time/correlation-scoped result set against a bounded,
documented set of well-known reference fields
(`actor.id`/`data.agentId`/`data.assignedAgentId`/`data.childAgentId` for
`agentId`; `data.taskId`/`data.parentTaskId`/`data.childTaskId` for
`taskId`) — a real, tested match, not a full-text scan of arbitrary nested
content.

**Context gathered from real tables** (never duplicated into a new
export-specific model): `Agent` + `AgentCertificate` for any referenced
agent, `Task` + `TaskDelegation` for any referenced task,
`PolicyVersion`(+`Policy` name) for any referenced policy version,
`ApprovalRequest`/`ApprovalDecision`/`AuthorizationGrant` for any
referenced approval request, `ToolInvocation` for any referenced task.
Risk-assessment data (score, reason codes) is already embedded in the
matched `AuditEvent`s' own `data` — no separate risk-assessment table
exists to join against.

**Signing**: reuses Phase 8's grant-signing crypto utility — literally the
same `toKey` HS256 key-derivation function `src/approvals/grant-token.util.ts`'s
`signGrantToken`/`verifyGrantToken` use (exported for this purpose,
otherwise unchanged), the same `jose` `SignJWT`/`jwtVerify` mechanism, and
the same `APPROVAL_GRANT_SIGNING_SECRET` config secret —
`src/evidence/evidence-signing.util.ts`. The signature covers
`sha256(canonicalize(bundleContent))` (`canonicalize` is Phase 9a's own
deterministic-JSON tool, `src/audit/canonical-json.ts`), not the raw JSON
text, so verification is independent of incidental re-serialization while
still failing for any real content change.

**Independent tamper-evidence**: the exported `events` array carries every
matched `AuditEvent`'s full hash-chain fields (`id`, `previousHash`,
`eventHash`, ...) in chain order — a recipient can recompute each event's
`eventHash` via the same public formula `computeEventHash` uses
(`src/audit/audit-hash.ts`) and confirm consecutive `previousHash`/
`eventHash` linkage _independent of trusting the export process itself_.
Full verification back to genesis additionally requires either the first
exported event's `previousHash` being `null`, or a separately-trusted
`GET /audit/verify` call against this tenant — the bundle alone proves
_internal_ consistency of the exported segment, not "this is the complete
history."

## Retention (Section 48)

Default 30 days (`DEFAULT_AUDIT_RETENTION_WINDOW_MS`,
`src/audit/retention/audit-retention.constants.ts`). **No API/CLI path
deletes an individual `AuditEvent` row** — the only place `auditEvent.deleteMany`
is ever called in this codebase is inside `AuditRetentionService.pruneTenantAuditEvents`
(`src/audit/retention/audit-retention.service.ts`), itself only reachable
via `AuditRetentionWorkflow`'s Temporal Activity.

`AuditRetentionWorkflow` (`src/temporal/workflows/audit-retention.workflow.ts`)
reuses Phase 8's Temporal worker process (`src/worker.main.ts`, now
bundling both `ApprovalWorkflow` and `AuditRetentionWorkflow` off one
`workflowsPath` — see `src/temporal/workflows/index.ts`). One execution
= one retention pass for one tenant:

1. Finds `AuditEvent` rows older than the retention window.
2. If none, a genuine no-op — no anchor, no `audit.retention_executed`
   event.
3. Otherwise, in one transaction: writes a new `AuditChainAnchor`
   (`tenantId`, `anchorHash` = the last-to-be-pruned event's own
   `eventHash`, `eventsPrunedCount`), then deletes the aged rows.
4. Writes a new `audit.retention_executed` `AuditEvent` via the real
   (not `recordSafely`) `AuditService.record` — this event's
   `previousHash` comes from the tenant's current `AuditChainState`
   exactly like any other event, naturally becoming the new chain tail.

Not wired to an automatic Temporal Schedule this phase — started directly
via `@temporalio/client`'s `workflow.start`/`.execute` (this phase's own
tests do exactly that). A future phase can add per-tenant Schedules
without changing the workflow/Activity themselves.

### `verifyAuditChain` is anchor-aware

Updated (`src/audit/audit.service.ts`) so a pruned chain still verifies:
the oldest _remaining_ event's `previousHash` is valid if it's `null`
(true genesis) **or** matches a known `AuditChainAnchor.anchorHash` for
this tenant — instead of requiring the (now-deleted) ancestor row to still
exist. Every event after the first is checked exactly as before, against
the _previous remaining_ event's own `eventHash`.

## Testing

- `test/audit-opensearch-indexing.e2e-spec.ts`: reindex is real (drop the
  index, run `AuditReindexService.reindexTenant`, confirm every Postgres
  `AuditEvent` is now present in OpenSearch); Kafka redelivery of the same
  `eventId` through the real `AuditIndexerService` doesn't double-index.
- `src/audit/ocsf/ocsf-mapper.spec.ts`: covered types match the documented
  shape; uncovered types are clearly labeled, never forced.
- `test/audit-live-sse.e2e-spec.ts`: a real triggered event (task
  creation via `POST /tasks`) arrives on an open `GET /events/live`
  connection for the correct tenant; a different tenant's open connection
  does not receive it.
- `test/evidence-export.e2e-spec.ts`: a bundle for a known scenario
  contains the expected events + context and its signature verifies;
  tampering the exported JSON afterward fails verification.
- `src/temporal/workflows/audit-retention.workflow.spec.ts`: the
  workflow's own approve/no-op logic, time-skipping `TestWorkflowEnvironment`,
  mocked Activities (mirrors `approval.workflow.spec.ts`).
- `test/audit-retention.e2e-spec.ts`: seeds events older than the window,
  runs `AuditRetentionWorkflow` against real Postgres/Temporal (an
  in-process worker, mirroring `test/approvals.e2e-spec.ts`), confirms old
  events are gone, an anchor was recorded, a `retention_executed` event
  exists, and `verifyAuditChain` still reports valid for the pruned chain.
