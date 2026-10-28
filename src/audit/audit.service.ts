import { randomUUID } from 'node:crypto';
import { Inject, Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import type {
  AuditEvent,
  Prisma,
  PrismaClient as TenantPrismaClient,
} from '../generated/tenant-client/client';
import { getCorrelationId } from '../logging/correlation-id.store';
import { AuditBatcher } from './audit-batcher';
import { computeEventHash } from './audit-hash';
import { AUDIT_PARTITIONS, partitionFor } from './audit-partition';
import type { AuditActor, AuditEventType } from './audit-event-types';
import {
  CURRENT_EVENT_VERSION,
  DomainEventEnvelope,
} from './domain-event-envelope';
import {
  CHECKPOINT_PUBLIC_KEYS,
  type CheckpointKeyLookup,
  type CheckpointPublicKey,
  checkpointHashOf,
  type PartitionHead,
  type PartitionRoot,
  verifyCheckpointSignature,
} from './checkpoint/checkpoint-format';
import { KafkaPublisherService } from './kafka-publisher.service';
import { merkleRoot } from './merkle';

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
  /** Which of the tenant's 64 chains (`src/audit/audit-partition.ts`). */
  partition: number;
  /** 1-based position within `partition`. */
  partitionSeq: bigint;
}

export type VerifyAuditChainResult =
  { valid: true } | { valid: false; brokenAt: string };

/** An event whose id, time and correlation are fixed when `record` is called. */
interface PendingAuditEvent {
  client: TenantPrismaClient;
  input: RecordAuditEventInput;
  id: string;
  correlationId: string;
  timestamp: Date;
  partition: number;
}

interface PartitionLockRow {
  partition: number;
  latestEventHash: string | null;
  latestSeq: bigint;
}

/**
 * The single write path for every `AuditEvent` (docs/audit-chain.md). No
 * other code inserts into `audit_events`/`audit_partition_state`, and there
 * is no update/delete path for either outside retention.
 *
 * Each tenant's log is 64 hash chains (`partitionFor` keys them by agent), so
 * one agent's events stay strictly ordered while unrelated agents append in
 * parallel. `record` goes through a per-tenant group commit (`AuditBatcher`:
 * ≤ 5 ms or 500 events per transaction); the caller's promise settles only
 * when its batch commits, so "record before acting" still holds.
 */
@Injectable()
export class AuditService implements OnModuleDestroy {
  private readonly logger = new Logger(AuditService.name);

  /**
   * How many `AuditEvent` rows `verifyAuditChain` holds in memory at once.
   * `GET /audit/verify` is reachable over HTTP and the pod's memory limit is
   * 768Mi, so the walk is keyset-paginated per partition rather than loaded
   * whole (release 2026-11-11 fix, kept).
   */
  private static readonly VERIFY_CHAIN_BATCH_SIZE = 1000;

  private readonly batcher = new AuditBatcher<PendingAuditEvent, AuditEvent>(
    (_tenantId, items) => this.flushBatch(items),
  );

  constructor(
    private readonly kafkaPublisher: KafkaPublisherService,
    @Inject(CHECKPOINT_PUBLIC_KEYS)
    private readonly checkpointKeys: CheckpointKeyLookup,
  ) {}

  /** Commits whatever is still queued before the process exits. */
  async onModuleDestroy(): Promise<void> {
    await this.batcher.close();
  }

  /**
   * Appends one event through the tenant's group commit and resolves once
   * its batch has committed. Publishing to Kafka happens after that, is not
   * awaited, and can never affect the Postgres write: the `AuditEvent` row is
   * the record, Kafka a downstream notification.
   */
  async record(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    input: RecordAuditEventInput,
  ): Promise<AuditEventRecord> {
    const event = await this.batcher.enqueue(
      tenantId,
      this.pending(tenantClient, input),
    );
    this.publishAfterCommit(event, tenantId, input);
    return event;
  }

  /**
   * Appends inside the caller's transaction, so the audited change and its audit event commit
   * or roll back together (ADR-0010: platform kill switch). Bypasses the batcher: it locks
   * only this event's partition row. Call the returned function after the transaction commits
   * to publish to Kafka.
   */
  async recordInTransaction(
    tx: Prisma.TransactionClient,
    tenantId: string,
    input: RecordAuditEventInput,
  ): Promise<() => void> {
    const [event] = await this.append(tx, [this.pending(undefined, input)]);
    return () => this.publishAfterCommit(event!, tenantId, input);
  }

  private pending(
    client: TenantPrismaClient | undefined,
    input: RecordAuditEventInput,
  ): PendingAuditEvent {
    return {
      client: client as TenantPrismaClient,
      input,
      id: randomUUID(),
      correlationId: input.correlationId ?? getCorrelationId() ?? randomUUID(),
      timestamp: new Date(),
      partition: partitionFor(input.actor, input.data),
    };
  }

  /**
   * One transaction per batch. Every item in a batch shares its tenant, so its
   * client. If the batch fails, each item is retried in its own transaction,
   * so one event Postgres refuses (say, `data` with U+0000) fails only its own
   * caller and cannot drop its batch-mates' records.
   */
  private async flushBatch(
    items: PendingAuditEvent[],
  ): Promise<(AuditEvent | Error)[]> {
    const client = items[0]!.client;
    try {
      return await client.$transaction((tx) => this.append(tx, items));
    } catch (error) {
      if (items.length === 1) throw error;
      const results: (AuditEvent | Error)[] = [];
      for (const item of items) {
        try {
          const [event] = await client.$transaction((tx) =>
            this.append(tx, [item]),
          );
          results.push(event!);
        } catch (itemError) {
          results.push(
            itemError instanceof Error
              ? itemError
              : new Error(String(itemError)),
          );
        }
      }
      return results;
    }
  }

  /**
   * Locks the touched partitions' rows **in ascending order** (two replicas
   * flushing overlapping batches therefore never deadlock, and a real row
   * lock means they never fork a chain), chains each item onto its
   * partition's tail in arrival order, inserts them, and advances the rows.
   */
  private async append(
    tx: Prisma.TransactionClient,
    items: PendingAuditEvent[],
  ): Promise<AuditEvent[]> {
    const partitions = [...new Set(items.map((i) => i.partition))].sort(
      (a, b) => a - b,
    );
    await tx.auditPartitionState.createMany({
      data: partitions.map((partition) => ({ partition })),
      skipDuplicates: true,
    });
    const locked = await tx.$queryRaw<PartitionLockRow[]>`
      SELECT "partition", "latestEventHash", "latestSeq"
      FROM "audit_partition_state"
      WHERE "partition" = ANY(${partitions}::int[])
      ORDER BY "partition"
      FOR UPDATE
    `;
    const tails = new Map(
      locked.map((row) => [
        row.partition,
        { hash: row.latestEventHash, seq: BigInt(row.latestSeq) },
      ]),
    );

    const rows = items.map((item) => {
      const tail = tails.get(item.partition) ?? { hash: null, seq: 0n };
      const previousHash = tail.hash;
      const partitionSeq = tail.seq + 1n;
      const eventHash = computeEventHash({
        id: item.id,
        eventType: item.input.eventType,
        correlationId: item.correlationId,
        actor: item.input.actor,
        timestamp: item.timestamp.toISOString(),
        data: item.input.data,
        previousHash,
      });
      tails.set(item.partition, { hash: eventHash, seq: partitionSeq });
      return {
        id: item.id,
        eventType: item.input.eventType,
        correlationId: item.correlationId,
        actor: item.input.actor as unknown as Prisma.InputJsonValue,
        timestamp: item.timestamp,
        data: (item.input.data ?? null) as Prisma.InputJsonValue,
        previousHash,
        eventHash,
        partition: item.partition,
        partitionSeq,
      };
    });

    const created = await tx.auditEvent.createManyAndReturn({ data: rows });
    const byId = new Map(created.map((event) => [event.id, event]));

    const touched = partitions.map((partition) => {
      const last = rows.filter((r) => r.partition === partition).at(-1)!;
      return {
        partition,
        id: last.id,
        hash: last.eventHash,
        seq: last.partitionSeq.toString(),
        count: rows.filter((r) => r.partition === partition).length,
      };
    });
    await tx.$executeRaw`
      UPDATE "audit_partition_state" AS s
      SET "latestEventId" = v.id,
          "latestEventHash" = v.hash,
          "latestSeq" = v.seq,
          "eventCount" = s."eventCount" + v.n,
          "updatedAt" = now()
      FROM unnest(
        ${touched.map((t) => t.partition)}::int[],
        ${touched.map((t) => t.id)}::text[],
        ${touched.map((t) => t.hash)}::text[],
        ${touched.map((t) => t.seq)}::text[]::bigint[],
        ${touched.map((t) => t.count)}::int[]
      ) AS v(p, id, hash, seq, n)
      WHERE s."partition" = v.p
    `;

    return items.map((item) => byId.get(item.id)!);
  }

  private publishAfterCommit(
    event: AuditEvent,
    tenantId: string,
    input: RecordAuditEventInput,
  ): void {
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
      partition: event.partition,
      partitionSeq: event.partitionSeq.toString(),
    };

    // Deliberately not awaited — see `record`.
    this.kafkaPublisher.publish(envelope).catch((error: unknown) => {
      this.logger.error(
        `Unexpected error publishing audit event "${event.id}" to Kafka: ${error instanceof Error ? error.message : String(error)}`,
      );
    });
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
   * Walks each of the tenant's 64 partitions in `partitionSeq` order,
   * recomputing every event's hash from its stored content and checking that
   * its `previousHash` is the previous event's `eventHash` in the same
   * partition (nothing removed, reordered or moved). Reports the first event
   * where that fails, not just "invalid" (Section 47).
   *
   * **Anchor-aware (Section 48)**: a partition's oldest *remaining* event may
   * follow history retention pruned; it is valid if its `previousHash` is
   * `null` (true genesis) or a known `AuditChainAnchor.anchorHash` for that
   * partition. Each partition's tail must match its `AuditPartitionState`
   * row (`brokenAt: 'audit_partition_state:<n>'`).
   *
   * **Bounded memory**: keyset pages of `VERIFY_CHAIN_BATCH_SIZE` per
   * partition; the running hash carries across page boundaries exactly as
   * across adjacent rows (`audit.service.spec.ts` pins a tamper in page two).
   *
   * **SEALs**: then walks the signed checkpoints in order — each must link
   * to the previous one, hash to its stored `checkpointHash`, carry a valid
   * signature by this tenant's key, and every root whose range still exists
   * must equal the Merkle root of those events (`brokenAt: 'checkpoint:<seq>'`).
   */
  async verifyAuditChain(
    tenantClient: TenantPrismaClient,
    tenantId: string,
  ): Promise<VerifyAuditChainResult> {
    // Read before walking: retention only ever adds anchors, so reading them
    // first can never make the walk reject a head an anchor written mid-walk
    // would have explained.
    const anchorsByPartition = new Map<number, Set<string>>();
    for (const anchor of await tenantClient.auditChainAnchor.findMany()) {
      const set = anchorsByPartition.get(anchor.partition) ?? new Set();
      set.add(anchor.anchorHash);
      anchorsByPartition.set(anchor.partition, set);
    }
    const states = new Map(
      (await tenantClient.auditPartitionState.findMany()).map((state) => [
        state.partition,
        state.latestEventHash ?? null,
      ]),
    );

    for (let partition = 0; partition < AUDIT_PARTITIONS; partition += 1) {
      const anchors = anchorsByPartition.get(partition) ?? new Set<string>();
      let expectedPreviousHash: string | null = null;
      let isFirstRemainingEvent = true;
      let lastSeq: bigint | null = null;

      for (;;) {
        const events = await this.fetchAuditEventBatch(
          tenantClient,
          partition,
          lastSeq,
        );
        if (events.length === 0) break;

        for (const event of events) {
          const previousHashIsValid = isFirstRemainingEvent
            ? event.previousHash === null || anchors.has(event.previousHash)
            : event.previousHash === expectedPreviousHash;
          isFirstRemainingEvent = false;
          if (!previousHashIsValid) return { valid: false, brokenAt: event.id };

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

        lastSeq = events[events.length - 1]!.partitionSeq;
        if (events.length < AuditService.VERIFY_CHAIN_BATCH_SIZE) break;
      }

      const stateHash = states.get(partition);
      const tailMatches = isFirstRemainingEvent
        ? // No events left: fine if never written, or if retention pruned
          // the whole partition (its tail is then a known anchor).
          stateHash === undefined ||
          stateHash === null ||
          anchors.has(stateHash)
        : stateHash === expectedPreviousHash;
      if (!tailMatches) {
        return { valid: false, brokenAt: `audit_partition_state:${partition}` };
      }
    }

    const brokenCheckpoint = await this.verifyCheckpoints(
      tenantClient,
      tenantId,
    );
    if (brokenCheckpoint !== null) {
      return { valid: false, brokenAt: `checkpoint:${brokenCheckpoint}` };
    }
    return { valid: true };
  }

  /** The `seq` of the first SEAL that fails, or `null` when all hold. */
  private async verifyCheckpoints(
    tenantClient: TenantPrismaClient,
    tenantId: string,
  ): Promise<string | null> {
    const oldestRemaining = new Map(
      (
        await tenantClient.$queryRaw<{ partition: number; oldest: bigint }[]>`
          SELECT "partition", MIN("partitionSeq") AS "oldest"
          FROM "audit_events" GROUP BY "partition"
        `
      ).map((r) => [r.partition, BigInt(r.oldest)]),
    );
    let key: CheckpointPublicKey | null = null;
    let previousHash: string | null = null;
    let expectedSeq = 1n;

    for (;;) {
      const page = await tenantClient.auditCheckpoint.findMany({
        where: { seq: { gte: expectedSeq } },
        orderBy: { seq: 'asc' },
        take: AuditService.VERIFY_CHAIN_BATCH_SIZE,
      });
      if (page.length === 0) return null;

      for (const cp of page) {
        const broken = cp.seq.toString();
        const roots = cp.roots as unknown as PartitionRoot[];
        const partitionHeads = cp.partitionHeads as unknown as PartitionHead[];
        if (
          cp.seq !== expectedSeq ||
          cp.previousCheckpointHash !== previousHash
        ) {
          return broken;
        }
        const recomputed = checkpointHashOf({
          seq: cp.seq,
          createdAt: cp.createdAt,
          partitionHeads,
          roots,
          previousCheckpointHash: cp.previousCheckpointHash,
        });
        key ??= await this.checkpointKeys.publicKey(tenantId);
        if (
          recomputed !== cp.checkpointHash ||
          cp.keyId !== key.keyId ||
          !verifyCheckpointSignature(
            cp.checkpointHash,
            cp.signature,
            key.publicKeyPem,
          )
        ) {
          return broken;
        }
        for (const r of roots) {
          const from = BigInt(r.fromSeq);
          const to = BigInt(r.toSeq);
          const oldest = oldestRemaining.get(r.partition);
          // Retention pruned this range (or its start): nothing left to recompute.
          if (oldest === undefined || from < oldest) continue;
          const events = await tenantClient.auditEvent.findMany({
            where: {
              partition: r.partition,
              partitionSeq: { gte: from, lte: to },
            },
            orderBy: { partitionSeq: 'asc' },
            select: { eventHash: true },
          });
          if (
            BigInt(events.length) !== to - from + 1n ||
            merkleRoot(events.map((e) => e.eventHash)) !== r.root
          ) {
            return broken;
          }
        }
        previousHash = cp.checkpointHash;
        expectedSeq += 1n;
      }
    }
  }

  /** One keyset page of a partition, strictly after `afterSeq`. */
  private async fetchAuditEventBatch(
    tenantClient: TenantPrismaClient,
    partition: number,
    afterSeq: bigint | null,
  ): Promise<AuditEvent[]> {
    return tenantClient.auditEvent.findMany({
      where:
        afterSeq === null
          ? { partition }
          : { partition, partitionSeq: { gt: afterSeq } },
      orderBy: { partitionSeq: 'asc' },
      take: AuditService.VERIFY_CHAIN_BATCH_SIZE,
    });
  }
}
