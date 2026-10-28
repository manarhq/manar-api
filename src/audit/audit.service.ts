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
  anchorDigestOf,
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
  partitionSeq: number;
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
  latestSeq: number;
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

  /**
   * How long events may sit after the last SEAL, measured by that SEAL's
   * signed time. The worker seals every second; two minutes absorbs a worker
   * restart. Past it, uncovered events mean SEALs were deleted (or sealing
   * has stopped), and verification fails closed.
   */
  static SEAL_GRACE_MS = 120_000;

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
        { hash: row.latestEventHash, seq: Number(row.latestSeq) },
      ]),
    );

    const rows = items.map((item) => {
      const tail = tails.get(item.partition) ?? { hash: null, seq: 0 };
      const previousHash = tail.hash;
      const partitionSeq = tail.seq + 1;
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
        seq: last.partitionSeq,
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
        ${touched.map((t) => t.seq)}::int[],
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
      partitionSeq: event.partitionSeq,
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
   * Where retention pruned the start of a range, the surviving tail is still
   * checked against the signed partition head. Every head the last SEAL
   * signed must still exist or be explained by retention. Events after the
   * last SEAL are accepted only while that SEAL is younger than
   * `SEAL_GRACE_MS` by its own signed time, so deleting SEALs, or forging
   * event timestamps, is reported (`brokenAt: 'unsealed:<partition>'`).
   */
  async verifyAuditChain(
    tenantClient: TenantPrismaClient,
    tenantId: string,
  ): Promise<VerifyAuditChainResult> {
    // Read before walking: retention only ever adds anchors, so reading them
    // first can never make the walk reject a head an anchor written mid-walk
    // would have explained.
    const anchorsByPartition = await this.verifiedAnchors(
      tenantClient,
      tenantId,
    );
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
      let lastSeq: number | null = null;

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

    const sealed = await this.verifyCheckpoints(tenantClient, tenantId);
    if (sealed.broken !== null) {
      return { valid: false, brokenAt: `checkpoint:${sealed.broken}` };
    }

    const extents = new Map(
      (
        await tenantClient.$queryRaw<
          { partition: number; oldest: number; newest: number; firstAt: Date }[]
        >`
          SELECT "partition", MIN("partitionSeq") AS "oldest",
                 MAX("partitionSeq") AS "newest", MIN("timestamp") AS "firstAt"
          FROM "audit_events" GROUP BY "partition"
        `
      ).map((r) => [
        r.partition,
        {
          oldest: Number(r.oldest),
          newest: Number(r.newest),
          firstAt: new Date(r.firstAt),
        },
      ]),
    );
    const last = sealed.last;

    if (last === null) {
      // No SEAL left, but the tenant key exists (outside the audit tables):
      // SEALs were written once, so they were deleted.
      const [firstPartition] = extents.keys();
      if (
        firstPartition !== undefined &&
        (await this.checkpointKeys.hasKey(tenantId))
      ) {
        return { valid: false, brokenAt: `unsealed:${firstPartition}` };
      }
      // Never sealed (a new tenant, or just upgraded): the events' own
      // timestamps are the only clock left.
      const cutoff = Date.now() - AuditService.SEAL_GRACE_MS;
      for (const [partition, extent] of extents) {
        if (extent.firstAt.getTime() < cutoff) {
          return { valid: false, brokenAt: `unsealed:${partition}` };
        }
      }
      return { valid: true };
    }

    // Every head the last SEAL signed still exists unchanged, or retention
    // pruned it (later events remain, or an anchor names it). Catches a
    // deleted partition or tail that the chain walk alone cannot see.
    for (const head of last.heads) {
      const seq = Number(head.seq);
      const row = await tenantClient.auditEvent.findUnique({
        where: {
          partition_partitionSeq: {
            partition: head.partition,
            partitionSeq: seq,
          },
        },
        select: { eventHash: true },
      });
      const extent = extents.get(head.partition);
      const pruned =
        (extent !== undefined && extent.oldest > seq) ||
        (anchorsByPartition.get(head.partition)?.has(head.eventHash) ?? false);
      if (row ? row.eventHash !== head.eventHash : !pruned) {
        return { valid: false, brokenAt: `checkpoint:${last.seq}` };
      }
    }

    // Events after the last SEAL are fine only while that SEAL is recent by
    // its own signed time; event timestamps can be rewritten, it cannot.
    if (Date.now() - last.createdAt.getTime() > AuditService.SEAL_GRACE_MS) {
      const headSeq = new Map(
        last.heads.map((h) => [h.partition, Number(h.seq)]),
      );
      for (const [partition, extent] of extents) {
        if (extent.newest > (headSeq.get(partition) ?? 0)) {
          return { valid: false, brokenAt: `unsealed:${partition}` };
        }
      }
    }
    return { valid: true };
  }

  /**
   * Retention anchors that may excuse pruned history, by partition: those
   * signed with the tenant key over `anchorDigestOf`, plus unsigned anchors
   * in partition 0, which only pre-partitioning retention could have written
   * (a planted unsigned anchor there is the one residual; see ADR-0014).
   */
  private async verifiedAnchors(
    tenantClient: TenantPrismaClient,
    tenantId: string,
  ): Promise<Map<number, Set<string>>> {
    const anchors = await tenantClient.auditChainAnchor.findMany();
    let key: CheckpointPublicKey | null = null;
    const byPartition = new Map<number, Set<string>>();
    for (const anchor of anchors) {
      let accepted = anchor.signature === null && anchor.partition === 0;
      if (anchor.signature !== null) {
        key ??= await this.checkpointKeys.publicKey(tenantId);
        accepted = verifyCheckpointSignature(
          anchorDigestOf({
            tenantId: anchor.tenantId,
            partition: anchor.partition,
            anchorHash: anchor.anchorHash,
            eventsPrunedCount: anchor.eventsPrunedCount,
          }),
          anchor.signature,
          key.publicKeyPem,
        );
      }
      if (!accepted) continue;
      const set = byPartition.get(anchor.partition) ?? new Set<string>();
      set.add(anchor.anchorHash);
      byPartition.set(anchor.partition, set);
    }
    return byPartition;
  }

  /**
   * The `seq` of the first SEAL that fails (or `null`), and the last SEAL:
   * its signed time and partition heads.
   */
  private async verifyCheckpoints(
    tenantClient: TenantPrismaClient,
    tenantId: string,
  ): Promise<{
    broken: string | null;
    last: { seq: string; createdAt: Date; heads: PartitionHead[] } | null;
  }> {
    const oldestRemaining = new Map(
      (
        await tenantClient.$queryRaw<{ partition: number; oldest: number }[]>`
          SELECT "partition", MIN("partitionSeq") AS "oldest"
          FROM "audit_events" GROUP BY "partition"
        `
      ).map((r) => [r.partition, Number(r.oldest)]),
    );
    let key: CheckpointPublicKey | null = null;
    let previousHash: string | null = null;
    let expectedSeq = 1n;
    let last: { seq: string; createdAt: Date; heads: PartitionHead[] } | null =
      null;
    const fail = (seq: bigint) => ({ broken: seq.toString(), last });

    for (;;) {
      const page = await tenantClient.auditCheckpoint.findMany({
        where: { seq: { gte: expectedSeq } },
        orderBy: { seq: 'asc' },
        take: AuditService.VERIFY_CHAIN_BATCH_SIZE,
      });
      if (page.length === 0) return { broken: null, last };

      for (const cp of page) {
        const roots = cp.roots as unknown as PartitionRoot[];
        const partitionHeads = cp.partitionHeads as unknown as PartitionHead[];
        if (
          cp.seq !== expectedSeq ||
          cp.previousCheckpointHash !== previousHash
        ) {
          return fail(cp.seq);
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
          return fail(cp.seq);
        }
        for (const r of roots) {
          const from = Number(r.fromSeq);
          const to = Number(r.toSeq);
          const oldest = oldestRemaining.get(r.partition);
          if (oldest === undefined || from < oldest) {
            // Retention pruned the start of this range, so its root can't be
            // recomputed; the surviving tail must still match the signed head.
            if (oldest !== undefined && oldest <= to) {
              const head = partitionHeads.find(
                (h) => h.partition === r.partition && Number(h.seq) === to,
              );
              const tail = await tenantClient.auditEvent.findUnique({
                where: {
                  partition_partitionSeq: {
                    partition: r.partition,
                    partitionSeq: to,
                  },
                },
                select: { eventHash: true },
              });
              if (!head || !tail || tail.eventHash !== head.eventHash) {
                return fail(cp.seq);
              }
            }
            continue;
          }
          const events = await tenantClient.auditEvent.findMany({
            where: {
              partition: r.partition,
              partitionSeq: { gte: from, lte: to },
            },
            orderBy: { partitionSeq: 'asc' },
            select: { eventHash: true },
          });
          if (
            events.length !== to - from + 1 ||
            merkleRoot(events.map((e) => e.eventHash)) !== r.root
          ) {
            return fail(cp.seq);
          }
        }
        previousHash = cp.checkpointHash;
        expectedSeq += 1n;
        last = {
          seq: cp.seq.toString(),
          createdAt: cp.createdAt,
          heads: partitionHeads,
        };
      }
    }
  }

  /** One keyset page of a partition, strictly after `afterSeq`. */
  private async fetchAuditEventBatch(
    tenantClient: TenantPrismaClient,
    partition: number,
    afterSeq: number | null,
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
