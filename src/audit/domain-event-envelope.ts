/**
 * Phase 9a (Section 29). The wire shape every `AuditEvent` is also
 * published to Kafka as, on the single `manar.audit-events` topic — one
 * topic is enough for MVP (`eventType` is what a consumer filters on,
 * rather than 30 topics for 30 event types, which would be unnecessary
 * operational overhead this stage). Consumers must be idempotent (Section
 * 29): Kafka delivery is at-least-once, never exactly-once, so a future
 * consumer (Phase 9b's OpenSearch indexer, e.g.) must upsert by `eventId`,
 * never blindly append — see `test/audit-kafka-idempotency.e2e-spec.ts` for
 * a small test consumer proving this contract is real, not aspirational.
 */
export interface DomainEventEnvelope {
  /** Same value as the `AuditEvent.id` this envelope was published for. */
  eventId: string;
  /** Section 29's event-type catalog — see `audit-event-types.ts`. */
  eventType: string;
  /**
   * Schema version of this envelope's `data` shape for `eventType` — every
   * event this phase publishes is version 1 (no prior version exists yet to
   * migrate from); exists so a future breaking change to one event type's
   * `data` shape has somewhere to signal that without guessing from
   * `eventType` alone.
   */
  eventVersion: number;
  tenantId: string;
  /** ISO-8601 — same value as the source `AuditEvent.timestamp`. */
  timestamp: string;
  correlationId: string;
  actor: { type: 'human' | 'agent' | 'system'; id: string };
  data: unknown;
  /**
   * Phase 9b addition — the same tamper-evident hash-chain linkage fields
   * `AuditEvent` itself carries (`src/audit/audit.service.ts`), included so
   * a downstream consumer (`AuditIndexerService`, indexing into OpenSearch
   * — see `docs/audit-chain.md`) can carry a faithful copy of the chain
   * position without a separate Postgres round-trip per message.
   * Deliberately **optional** (not added to the required base envelope
   * shape above): `test/audit-kafka-idempotency.e2e-spec.ts` (Phase 9a)
   * constructs its own literal envelopes without these fields, and must
   * keep passing unmodified — see that suite's own doc comment. Every
   * envelope `AuditService.record` actually publishes sets all three.
   */
  previousHash?: string | null;
  eventHash?: string;
  sequence?: number;
  /** The event's audit partition and its position in it (decimal string: a bigint). */
  partition?: number;
  partitionSeq?: string;
}

/** This phase ships exactly one envelope schema version — see `DomainEventEnvelope.eventVersion`'s doc comment. */
export const CURRENT_EVENT_VERSION = 1;

/**
 * The single Kafka topic every domain event this phase produces is
 * published to (Section 29 — see module doc comment). Matches
 * `deploy/docker-compose.yml`'s Kafka service and `KafkaConfigSchema`'s
 * default.
 */
export const AUDIT_EVENTS_TOPIC = 'manar.audit-events';
