# Phase 9b: OpenSearch Indexing, OCSF, Live SSE, Evidence Export & Retention — Design

Status: Approved (autonomous execution)
Scope: `manar-api` only
Depends on: Phase 9a (`AuditEvent`, `AuditChainState`, Kafka event
backbone, `AuditService`) — must run after it, consumes what it produces

## Purpose

Sections 45, 50 (OCSF), 48-49 (retention/evidence), 62 (live activity):
turn the append-only audit chain into something searchable, streamable,
exportable, and correctly aged out.

## Redis + OpenSearch infra

Add both to `deploy/docker-compose.yml`. Redis's approved use here
(Section 30) is SSE fanout — a pub/sub channel per tenant that any API
replica can subscribe to, so live events reach connected dashboard
clients regardless of which replica received the original write.

## OpenSearch indexing

A Kafka consumer (`AuditIndexerService`) subscribing to Phase 9a's
`manar.audit-events` topic, **upserting by `eventId`** into a per-tenant
(or tenant-tagged single) OpenSearch index — idempotent, per Section
29's requirement, so redelivery never double-indexes. Postgres remains
authoritative (Section 45) — write a real test proving this: drop/empty
the OpenSearch index, run a `reindex` operation, confirm it's fully
reconstructable from Postgres alone. Implement that reindex as an
explicit command (`pnpm manar audit:reindex --tenant <id>`, reusing
Phase 2's `nest-commander` CLI convention) reading every `AuditEvent`
from Postgres and upserting it — this IS the disaster-recovery path,
build and test it for real, don't just assert it conceptually.

## OCSF mapping (Section 50)

Research OCSF's current official schema (pin the specific version you
target, document it). Pick 2-3 OCSF event classes that genuinely fit a
meaningful subset of Manar's audit events (e.g. authorization decisions,
authentication/enrollment events) — do not force every Manar event type
into an ill-fitting OCSF class. Build a mapping layer
(`src/audit/ocsf/`) that transforms an `AuditEvent` into its OCSF
representation for the event types it covers, and returns the event
unmapped (or in a clearly-labeled Manar-native shape) for types with no
good OCSF fit — document that gap rather than inventing a fake mapping.
Where a genuinely Manar-specific field has no OCSF equivalent, add it as
a documented extension field, not by repurposing an unrelated official
field. Write `docs/` coverage of exactly which event types map to which
OCSF class and why (folds into `docs/audit-chain.md` from 9a, or a new
`docs/ocsf-mapping.md` — your call).

## Live SSE (Section 62)

`GET /events/live` (JWT-guarded, human-facing, tenant-scoped): an SSE
endpoint. `AuditService.record` (9a) — or a thin subscriber sitting next
to the Kafka consumer — publishes each new event to that tenant's Redis
pub/sub channel; the SSE endpoint subscribes to it for the duration of
the connection and streams matching events. Prove this is real: a test
that triggers a real audit-worthy action (e.g. an authorization denial
via the real API) while an SSE connection is open, and asserts the event
arrives over that connection — not a polling-based fake.

## Evidence export (Section 49)

`POST /evidence/export` (JWT-guarded, role `AUDITOR`/`SECURITY_ADMIN`/
`TENANT_OWNER`): accepts a filter (time window, and/or `agentId`/
`taskId`/`correlationId`), gathers the matching `AuditEvent`s plus
directly-relevant context already available from prior phases
(agent identity/cert metadata, task/delegation chain, policy version,
risk assessment, approval decision, tool invocation — pull from the real
tables, don't duplicate data into a new export-specific model), and
returns a signed/hashed JSON bundle (reuse Phase 8's grant-signing
crypto utility rather than inventing a second signing mechanism).
Include enough of the audit chain segment to let a recipient verify
those specific events weren't tampered with independent of trusting this
export process. A human-readable summary alongside the JSON is
desirable but the JSON is the actual evidence artifact — don't skip it
in favor of only a nice-looking report.

## Retention (Section 48)

Default 30 days. **No API/CLI path lets a tenant admin directly delete
individual `AuditEvent` rows** — deletion only happens via a dedicated,
scheduled Temporal workflow (`AuditRetentionWorkflow`, reuse Phase 8's
Temporal worker process) that:

1. Finds events older than the retention window.
2. Before deleting, records the last-to-be-deleted event's `eventHash`
   as a new `AuditChainAnchor` (new small model: `tenantId`, `anchorHash`,
   `anchoredAt`, `eventsPrunedCount`) — this is what lets
   `verifyAuditChain` (9a) keep working after old events are gone: chain
   verification starts from the oldest _remaining_ event and confirms
   its `previousHash` matches the most recent anchor rather than
   expecting to find that ancestor row.
3. Deletes the aged-out rows.
4. Writes a new `AuditEvent` _about the retention run itself_
   (`audit.retention_executed` or similar) — the deletion is itself
   auditable, per the spec's explicit requirement, and this new event
   naturally becomes the new chain tail.
5. Update `verifyAuditChain` (9a) to be anchor-aware: valid if either
   `previousHash === null` (true genesis) or `previousHash` matches a
   known `AuditChainAnchor.anchorHash` for that tenant.

## Testing

- OpenSearch reindex is real: empty the index, run `audit:reindex`,
  confirm every Postgres `AuditEvent` is now searchable/present.
- Kafka redelivery of the same `eventId` doesn't double-index (extends
  9a's idempotency test to the real indexer, not a throwaway test
  consumer).
- OCSF-mapped output for a covered event type matches the documented
  schema shape; an uncovered type is clearly labeled as such, not
  silently forced into a wrong class.
- SSE: real triggered event arrives on an open connection scoped to the
  correct tenant; a _different_ tenant's open connection does NOT
  receive it (tenant isolation on the live feed — this is a real
  invariant, not a nice-to-have, test it explicitly).
- Evidence export: bundle for a known scenario contains the expected
  audit events + context, and its signature/hash verifies; tampering the
  exported JSON after the fact makes verification fail.
- Retention: seed events older than the window, run
  `AuditRetentionWorkflow` (via Temporal's test environment, time-skipped
  — reuse Phase 8's testing approach), confirm old events are gone, an
  anchor was recorded, a `retention_executed` event exists, and
  `verifyAuditChain` still reports valid for the pruned chain.
- Existing Phase 4-9a e2e suites still pass unmodified.

## Out of scope this phase

- Webhooks / external SIEM export (later phase — this phase's OCSF
  mapping is the foundation that phase will reuse, not the delivery
  mechanism itself)
- Full compliance-framework mapping (Section 55, later phase)
- Multi-index sharding/lifecycle policies beyond a sane default
