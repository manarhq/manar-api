import { randomUUID } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import type {
  AuditEvent,
  Prisma,
  PrismaClient as TenantPrismaClient,
} from '../generated/tenant-client/client';
import { getCorrelationId } from '../logging/correlation-id.store';
import { computeEventHash } from './audit-hash';
import type { AuditActor, AuditEventType } from './audit-event-types';
import {
  CURRENT_EVENT_VERSION,
  DomainEventEnvelope,
} from './domain-event-envelope';
import { KafkaPublisherService } from './kafka-publisher.service';

export interface RecordAuditEventInput {
  eventType: AuditEventType;
  actor: AuditActor;
  /** The actual decision inputs (Section 46) — never the resolved credential value for a tool invocation event. */
  data: unknown;
  /**
   * Reuses the request's `x-correlation-id` when this call happens inside
   * an HTTP request's async chain — see `getCorrelationId`'s doc comment.
   * Explicit override for call sites with no such context (the separate
   * Temporal worker process, which never imports `LoggingModule` — see
   * `src/temporal/worker-app.module.ts`'s doc comment); falls back to a
   * freshly generated UUID if neither is available.
   */
  correlationId?: string;
}

export interface AuditEventRecord {
  id: string;
  eventType: string;
  correlationId: string;
  actor: unknown;
  timestamp: Date;
  data: unknown;
  previousHash: string | null;
  eventHash: string;
}

export type VerifyAuditChainResult =
  { valid: true } | { valid: false; brokenAt: string };

interface AuditChainStateRow {
  latestEventHash: string | null;
}

/**
 * Phase 9a (Sections 46-47, 29 — see docs/audit-chain.md). The single write
 * path for every `AuditEvent` in this codebase — no other code anywhere
 * inserts into `audit_events`/`audit_chain_state`, and there is no update/
 * delete path for either (append-only, by construction: `AuditEvent` has no
 * mutable fields any service ever writes to after creation).
 */
@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  /** Fixed, known singleton row id — see `AuditChainState`'s schema doc comment. */
  static readonly SINGLETON_ID = 'singleton';

  /**
   * How many `AuditEvent` rows `verifyAuditChain` holds in memory at once.
   *
   * Release 2026-11-11 reliability fix: this method used to materialize the
   * *entire* `audit_events` table in one `findMany` before hashing anything.
   * `GET /audit/verify` is reachable over HTTP by any `AUDITOR`/
   * `SECURITY_ADMIN`/`TENANT_OWNER`, and the pod's memory limit is 768Mi
   * (deploy/helm/manar-api/values.yaml) — so a single large tenant's
   * verification request was enough to OOM-kill the replica handling it,
   * taking every other in-flight request on that pod down with it.
   *
   * Verification is a *sequential* walk: it only ever needs the previous
   * event's `eventHash` to check the next one, so the whole table never has
   * to be resident. Batching bounds peak memory at roughly this many rows
   * regardless of chain length, at the cost of one extra round trip per
   * batch. 1000 is large enough that the round trips stay negligible next
   * to the SHA-256 work, and small enough that a batch of even unusually
   * fat `data` payloads is a few MB rather than hundreds.
   */
  private static readonly VERIFY_CHAIN_BATCH_SIZE = 1000;

  constructor(private readonly kafkaPublisher: KafkaPublisherService) {}

  /**
   * Transactional read-modify-write against `AuditChainState`: locks the
   * singleton row with `SELECT ... FOR UPDATE` (a real Postgres row lock,
   * held for the duration of this transaction — see that model's schema doc
   * comment for why this, and not an in-memory mutex, is what actually
   * prevents two concurrent callers, even across separate API replicas,
   * from forking the chain by both computing the same `previousHash`),
   * computes the new event's `eventHash`, inserts the `AuditEvent`, and
   * advances `AuditChainState` — all inside one transaction, so a crash
   * between any two of those steps leaves the chain exactly as it was
   * before this call started (transactional atomicity), never partially
   * advanced.
   *
   * Publishing to Kafka happens **after** that transaction has already
   * committed, and is neither awaited by the caller nor allowed to affect
   * the already-successful Postgres write in any way — `KafkaPublisherService.publish`
   * itself never throws (internally retried/logged), and this method
   * doesn't await it, specifically so a Kafka outage adds no latency to
   * hot authorization-decision call sites (`AuthorizationService.authorize`
   * is by far the most frequent caller of this method). The `AuditEvent`
   * row is the authoritative record; Kafka is a downstream notification a
   * future consumer (Phase 9b) reads, never a dependency this method's
   * success depends on.
   */
  async record(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    input: RecordAuditEventInput,
  ): Promise<AuditEventRecord> {
    const correlationId =
      input.correlationId ?? getCorrelationId() ?? randomUUID();
    const timestamp = new Date();
    const id = randomUUID();

    const event = await tenantClient.$transaction(async (tx) => {
      // Ensures the singleton row exists without a separate init step (the
      // same "resolve-or-create automatically" posture
      // `OpenFgaClientService.onModuleInit` establishes elsewhere — see
      // docs/authorization-model.md) — a no-op `ON CONFLICT DO NOTHING`-style
      // update for every call after the very first one for this tenant.
      await tx.auditChainState.upsert({
        where: { id: AuditService.SINGLETON_ID },
        update: {},
        create: { id: AuditService.SINGLETON_ID },
      });

      const rows = await tx.$queryRaw<AuditChainStateRow[]>`
        SELECT "latestEventHash" FROM "audit_chain_state"
        WHERE "id" = ${AuditService.SINGLETON_ID}
        FOR UPDATE
      `;
      const previousHash = rows[0]?.latestEventHash ?? null;

      const eventHash = computeEventHash({
        id,
        eventType: input.eventType,
        correlationId,
        actor: input.actor,
        timestamp: timestamp.toISOString(),
        data: input.data,
        previousHash,
      });

      const created = await tx.auditEvent.create({
        data: {
          id,
          eventType: input.eventType,
          correlationId,
          actor: input.actor as unknown as Prisma.InputJsonValue,
          timestamp,
          data: (input.data ?? null) as Prisma.InputJsonValue,
          previousHash,
          eventHash,
        },
      });

      await tx.auditChainState.update({
        where: { id: AuditService.SINGLETON_ID },
        data: {
          latestEventId: created.id,
          latestEventHash: created.eventHash,
          eventCount: { increment: 1 },
        },
      });

      return created;
    });

    const envelope: DomainEventEnvelope = {
      eventId: event.id,
      eventType: event.eventType,
      eventVersion: CURRENT_EVENT_VERSION,
      tenantId,
      timestamp: event.timestamp.toISOString(),
      correlationId: event.correlationId,
      actor: input.actor,
      data: input.data,
      previousHash: event.previousHash,
      eventHash: event.eventHash,
      sequence: event.sequence,
    };

    // Deliberately not awaited — see method doc comment.
    this.kafkaPublisher.publish(envelope).catch((error: unknown) => {
      this.logger.error(
        `Unexpected error publishing audit event "${event.id}" to Kafka: ${error instanceof Error ? error.message : String(error)}`,
      );
    });

    return event;
  }

  /**
   * Same as `record`, but never throws — logs and swallows any failure
   * instead. Every retrofit call site elsewhere in this codebase
   * (`AgentsService`, `TasksService`, `DelegationService`,
   * `AuthorizationService`, `CredentialBrokerService`, `GrantService`,
   * `ApprovalRequestService`/`ToolInvokeController`, `PolicyService`) uses
   * this method, not `record` directly: this phase's retrofit work must
   * never change any existing decision's outcome or response shape, and a
   * rare Postgres failure specific to the audit tables (a full disk, a
   * migration not yet applied, ...) must not therefore also fail the
   * actual authorization decision / task creation / tool invocation this
   * call is merely recording alongside. `record` itself stays available
   * (and does propagate failures) for `verifyAuditChain`'s own test suite
   * and any caller that specifically wants to observe an audit-write
   * failure.
   */
  async recordSafely(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    input: RecordAuditEventInput,
  ): Promise<AuditEventRecord | undefined> {
    try {
      return await this.record(tenantClient, tenantId, input);
    } catch (error) {
      this.logger.error(
        `Failed to record audit event (eventType="${input.eventType}") for tenant "${tenantId}": ${error instanceof Error ? error.message : String(error)}`,
      );
      return undefined;
    }
  }

  /**
   * Walks every `AuditEvent` in this tenant's chain in the order it was
   * actually recorded (`sequence`), recomputing each row's hash from its
   * own stored content and confirming both that it matches the stored
   * `eventHash` (this row wasn't tampered with) AND that its `previousHash`
   * matches the previous row's `eventHash` (no row was removed, reordered,
   * or had its position in the chain altered). Reports the specific
   * `AuditEvent.id` where verification first fails, not just "invalid" —
   * Section 47's mandatory "modify an old event, prove verification fails
   * *and correctly reports where*" test depends on this.
   *
   * **Anchor-aware (Phase 9b, Section 48)**: the very first event walked
   * (the oldest one *remaining*, not necessarily this tenant's true
   * genesis event — `AuditRetentionWorkflow` may have pruned everything
   * before it) is valid if its `previousHash` is either `null` (true
   * genesis — retention has never run for this tenant) OR matches a known
   * `AuditChainAnchor.anchorHash` for this tenant (`src/audit/retention/`)
   * — the hash `AuditRetentionWorkflow` recorded for the last event it
   * pruned, immediately before deleting it. Every event *after* the first
   * is checked exactly as before (against the *previous remaining* event's
   * own `eventHash`) — retention never breaks linkage among surviving
   * events, only the link to history that no longer exists.
   *
   * Also confirms the chain's *tail* matches `AuditChainState` — a
   * mismatch there (the bookkeeping row disagreeing with the event table
   * itself) is reported as `brokenAt: 'audit_chain_state'`, distinct from
   * any single event's own id.
   *
   * **Bounded memory (release 2026-11-11)**: the walk is fetched in
   * `VERIFY_CHAIN_BATCH_SIZE`-row batches (keyset-paginated on `sequence`,
   * see `fetchAuditEventBatch`) rather than as one whole-table `findMany`.
   * The check itself is byte-for-byte the same one it always was: the walk
   * is inherently sequential — each event is validated against nothing but
   * the *immediately preceding* event's `eventHash` — so carrying
   * `expectedPreviousHash` across a batch boundary is exactly equivalent to
   * carrying it across two adjacent array elements. Nothing about batching
   * lets a tampered event in a later batch slip through; see
   * `audit.service.spec.ts`'s cross-batch tamper test, which pins that.
   */
  async verifyAuditChain(
    tenantClient: TenantPrismaClient,
  ): Promise<VerifyAuditChainResult> {
    // Read before the first batch (rather than after, as this used to read
    // it after the whole-table query): `AuditRetentionWorkflow` only ever
    // *adds* anchors, so reading them first can only ever make the walk
    // more permissive-by-a-hash-it-would-otherwise-not-recognize — never
    // less. Reading them later would leave a window in which retention
    // prunes history and writes its anchor while the walk is in progress,
    // and the walk then rejects the new oldest-remaining event for a
    // linkage the anchor it just missed would have explained.
    const knownAnchorHashes = new Set(
      (await tenantClient.auditChainAnchor.findMany()).map(
        (anchor) => anchor.anchorHash,
      ),
    );

    let expectedPreviousHash: string | null = null;
    let isFirstRemainingEvent = true;
    let lastSequence: number | null = null;

    for (;;) {
      const events = await this.fetchAuditEventBatch(
        tenantClient,
        lastSequence,
      );
      if (events.length === 0) break;

      for (const event of events) {
        const previousHashIsValid = isFirstRemainingEvent
          ? event.previousHash === null ||
            (event.previousHash !== null &&
              knownAnchorHashes.has(event.previousHash))
          : event.previousHash === expectedPreviousHash;
        isFirstRemainingEvent = false;

        if (!previousHashIsValid) {
          return { valid: false, brokenAt: event.id };
        }

        const recomputed = computeEventHash({
          id: event.id,
          eventType: event.eventType,
          correlationId: event.correlationId,
          actor: event.actor,
          timestamp: event.timestamp.toISOString(),
          data: event.data,
          previousHash: event.previousHash,
        });
        if (recomputed !== event.eventHash) {
          return { valid: false, brokenAt: event.id };
        }

        expectedPreviousHash = event.eventHash;
      }

      // A short batch means the table is exhausted — stop without paying
      // for one more round trip that can only come back empty.
      const lastEvent = events[events.length - 1];
      if (lastEvent === undefined) break;
      lastSequence = lastEvent.sequence;
      if (events.length < AuditService.VERIFY_CHAIN_BATCH_SIZE) break;
    }

    const state = await tenantClient.auditChainState.findUnique({
      where: { id: AuditService.SINGLETON_ID },
    });
    if (state && (state.latestEventHash ?? null) !== expectedPreviousHash) {
      return { valid: false, brokenAt: 'audit_chain_state' };
    }

    return { valid: true };
  }

  /**
   * One `VERIFY_CHAIN_BATCH_SIZE`-row page of this tenant's chain, in
   * `sequence` order, starting strictly after `afterSequence`.
   *
   * Keyset pagination (`WHERE sequence > ?`), deliberately not `skip`/
   * `take` offset pagination and not Prisma's `cursor` option:
   *
   * - Offset pagination would make the database re-scan and re-sort every
   *   already-verified row for each subsequent page, and — worse — would
   *   silently *skip* a row if retention pruned the head of the chain
   *   mid-walk, which for a chain verifier means reporting a break that
   *   isn't one.
   * - Prisma's `cursor` wants a uniquely-identifying field, and
   *   `AuditEvent.sequence` is a plain `Int @default(autoincrement())` —
   *   not declared `@unique` in the schema (prisma/tenant.prisma), even
   *   though Postgres's own sequence makes it so in practice. `WHERE >` is
   *   correct either way and doesn't depend on that distinction.
   *
   * Append-only-ness (see this class's doc comment) is what makes paging
   * safe at all: rows are never updated or reordered, so a row's
   * `sequence` — and therefore its position in this pagination — is fixed
   * from insert onward.
   */
  private async fetchAuditEventBatch(
    tenantClient: TenantPrismaClient,
    afterSequence: number | null,
  ): Promise<AuditEvent[]> {
    return tenantClient.auditEvent.findMany({
      where: afterSequence === null ? {} : { sequence: { gt: afterSequence } },
      orderBy: { sequence: 'asc' },
      take: AuditService.VERIFY_CHAIN_BATCH_SIZE,
    });
  }
}
