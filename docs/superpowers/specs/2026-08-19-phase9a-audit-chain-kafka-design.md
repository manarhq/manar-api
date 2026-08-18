# Phase 9a: Tamper-Evident Audit Chain & Kafka Event Backbone — Design

Status: Approved (autonomous execution)
Scope: `manar-api` only
Depends on: Phase 8 (approval workflow — one of the retrofit points below)
Followed by: Phase 9b (OpenSearch indexing, OCSF mapping, SSE live feed,
evidence export, retention — all consume what this phase produces, so
must run after it, not in parallel)

## Purpose

Sections 46-47, 29: every security-relevant action across the whole
product so far gets a real, cryptographically hash-chained `AuditEvent`,
and a Kafka backbone carries the same events as domain events for later
consumers (OpenSearch indexing, SSE, webhooks — all Phase 9b+). This
phase is mostly **retrofit** — instrumenting call sites that already
exist in Phases 4-8, not new business logic.

## Kafka infra

Add Kafka to `deploy/docker-compose.yml` (research current official
Kafka setup — KRaft mode, no ZooKeeper, is current practice; don't set
up a deprecated topology). One topic is enough for MVP (e.g.
`manar.audit-events`), envelope carries `eventType` — don't create
30 topics for 30 event types, that's unnecessary operational overhead
for this stage and consumers can filter on `eventType`.

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

Consumers must be idempotent (Section 29) — don't assume exactly-once;
Phase 9b's indexer must upsert by `eventId`, not blindly append.

## Data model (tenant DB)

- `AuditEvent`: `id`, `eventType`, `correlationId`, `actor` (Json —
  `{type, id}`), `timestamp`, `data` (Json — enough to reconstruct why a
  decision occurred, per Section 46: include the actual decision inputs,
  not just "denied"), `previousHash`, `eventHash`. Append-only —
  **no update/delete endpoint or code path anywhere in the application**;
  retention deletion (Phase 9b) is the one exception and goes through a
  dedicated, auditable workflow, not ad hoc code.
- `AuditChainState`: `id` (singleton per tenant — e.g. a fixed known ID
  or a `WHERE` unique constraint enforcing one row), `latestEventId`,
  `latestEventHash`, `eventCount`, `updatedAt`. Exists so appending the
  next event doesn't require scanning the whole table for the tail.

Migration.

## Canonical serialization (Section 47 — be precise here)

Hashing must be deterministic regardless of key insertion order. Write
an explicit canonicalization function (recursively sort object keys,
fixed number/string formatting) — do not rely on `JSON.stringify`'s
insertion-order behavior, and document why (a future refactor that
reorders how an event object is constructed must not silently break
chain verification). `eventHash = sha256(canonicalize({ ...event,
previousHash }))`. First event in a tenant's chain has `previousHash =
null`.

## `AuditService`

`record({ eventType, correlationId, actor, data }): Promise<AuditEvent>`:
loads `AuditChainState` for the tenant (locked/transactional to avoid a
race between two concurrent events computing the same `previousHash`),
computes the new event's hash, inserts the `AuditEvent`, updates
`AuditChainState`, and publishes the same envelope to Kafka. This must
be atomic enough that a crash between the Postgres write and the Kafka
publish doesn't corrupt the chain — the chain's integrity lives entirely
in Postgres; Kafka publishing failure should be retried/logged, not
allowed to roll back or block the audit write (the audit record is the
authoritative one, Kafka is a downstream notification).

`verifyAuditChain(tenantId): Promise<{ valid: boolean; brokenAt?: string }>`:
walks every `AuditEvent` in order, recomputes each hash from canonical
content + the recorded `previousHash`, confirms it matches the stored
`eventHash` AND that it matches the next event's `previousHash`. Expose
via an admin/auditor endpoint (`GET /audit/verify`, role `AUDITOR`/
`SECURITY_ADMIN`/`TENANT_OWNER`).

## Retrofit points (instrument these existing services — find their real current method names/locations, this list may not match exactly)

- Agent enrollment success/failure, agent revocation (Phase 4)
- Task creation, task delegation (Phase 5)
- Every `AuthorizationService.authorize` decision — `ALLOW`/`DENY`/
  `REQUIRE_APPROVAL`, with enough `data` to answer "why" (matched policy,
  risk score, OpenFGA result) per Section 46
- Approval request created, approval decision, grant issued (Phase 8)
- Tool invocation success/failure (Phase 7) — **never include the
  resolved credential in `data`**, this is a hard rule, write a test for
  it specifically (grep the actual stored `AuditEvent.data` in the test)
- Policy version published (Phase 6)

Use the event-type names from Section 29's catalog where they cover
these (`agent.enrolled`, `agent.revoked`, `task.created`, `task.delegated`,
`authorization.allowed`/`denied`/`pending_approval`, `approval.requested`/
`approved`/`denied`, `tool.invocation.started`/`completed`/`failed`,
`policy.published`).

## Testing

- Chain of N events verifies successfully.
- Tampering a stored `AuditEvent.data` (or `eventHash`) directly in the
  test DB, then calling `verifyAuditChain`, fails and correctly reports
  where (Section 47's exact mandatory test: "modify an old event in a
  test DB, prove verification fails").
- Concurrent `AuditService.record` calls (simulate two near-simultaneous
  audit-worthy actions) never produce two events with the same
  `previousHash` (no chain fork) — assert the resulting chain is still
  linear and verifies.
- Each retrofit point above actually produces an `AuditEvent` when
  exercised via its real API path (not called directly) — e.g. denying
  an action via `/agent/v1/authorize` produces an `authorization.denied`
  event with the real denial reason in `data`.
- Credential secrecy: a successful tool invocation's `AuditEvent.data`
  never contains the resolved credential value, under grep, not just
  code review.
- Kafka consumer-side idempotency: publish the same `eventId` twice
  (simulate a redelivery), a naive consumer that upserts by `eventId`
  ends up with one record, not two (this can be a small test consumer
  written just to prove the envelope/idempotency contract, since Phase
  9b's real indexer doesn't exist yet).
- Existing Phase 4-8 e2e suites still pass unmodified (you're adding
  audit calls alongside existing logic, not changing decisions).

## Docs

`docs/audit-chain.md` (Section 87) — the canonicalization approach, the
retrofit points, and how `verifyAuditChain` works.

## Out of scope this phase

- OpenSearch indexing, OCSF mapping, SSE live feed, evidence export,
  retention/deletion (all Phase 9b)
- Webhooks (later phase)
