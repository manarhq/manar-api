import { Injectable, Logger } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../../generated/tenant-client/client';
import { AuditService } from '../audit.service';
import { AuditCheckpointService } from '../checkpoint/audit-checkpoint.service';
import {
  anchorDigestOf,
  type PartitionHead,
} from '../checkpoint/checkpoint-format';
import { CheckpointSigner } from '../checkpoint/checkpoint-signer';
import { AUDIT_EVENT_TYPES } from '../audit-event-types';
import type {
  PruneAuditEventsInput,
  PruneAuditEventsResult,
} from '../../temporal/activities/audit-retention-activities.interface';

/**
 * Phase 9b (Retention, Section 48) — the real business logic behind
 * `AuditRetentionWorkflow`'s single Activity
 * (`src/temporal/activities/audit-retention.activities.ts`), the exact
 * same "a plain injectable service holds the real logic; the Temporal
 * Activities factory is a thin adapter around it" split
 * `GrantService`/`ApprovalActivitiesFactory` already establish (Section
 * 28 — see `docs/approvals.md`).
 *
 * No API/CLI path anywhere in this codebase calls `pruneTenantAuditEvents`
 * directly outside this service's own Activity wiring and this phase's
 * tests — deleting an individual `AuditEvent` row happens *only* through
 * this governed sequence, never ad hoc.
 */
@Injectable()
export class AuditRetentionService {
  private readonly logger = new Logger(AuditRetentionService.name);

  constructor(
    private readonly auditService: AuditService,
    private readonly signer: CheckpointSigner,
    private readonly checkpoints: AuditCheckpointService,
  ) {}

  /**
   * First seals what exists (so pruned events were sealed), then per audit
   * partition (each is its own hash chain):
   * 1. Finds the last event older than the retention window; everything up
   *    to it in that partition is pruned.
   * 2. If no partition has one, a genuine no-op (`prunedCount: 0`): no
   *    anchor, no `audit.retention_executed` event.
   * 3. Otherwise, in one transaction: one `AuditChainAnchor` per pruned
   *    partition naming that partition's last pruned `eventHash`, then the
   *    deletes — together, so a crash never leaves a deletion without its
   *    anchor (a retried Activity may leave a harmless duplicate anchor).
   * 4. Records `audit.retention_executed` through the real
   *    `AuditService.record` (not `recordSafely`: a failure must fail the
   *    Activity so Temporal retries it), listing every anchor.
   */
  async pruneTenantAuditEvents(
    tenantClient: TenantPrismaClient,
    input: PruneAuditEventsInput,
  ): Promise<PruneAuditEventsResult> {
    const cutoff = new Date(Date.now() - input.retentionWindowMs);
    // Seal before pruning: everything pruned is then covered by a SEAL, and
    // the tenant key never exists without one.
    await this.checkpoints.createCheckpoint(tenantClient, input.tenantId);
    // Never prune or sign anchors over a log that doesn't verify: retention
    // would otherwise bless tampered rows with the tenant key. The Activity
    // fails, Temporal retries, and the broken log is left for investigation.
    // Incremental: from the last verified SEAL, so the cost tracks what is
    // new rather than the tenant's whole history.
    const verified = await this.auditService.verifyAuditChain(
      tenantClient,
      input.tenantId,
      { incremental: true },
    );
    if (!verified.valid) {
      throw new Error(
        `Audit log for tenant "${input.tenantId}" does not verify (broken at ${verified.brokenAt}); not pruning`,
      );
    }

    // Prune only what a SEAL already covers: a partition is pruned no
    // further than the last SEAL's head for it (sealing is bounded per
    // round, so a long backlog may still be partly unsealed).
    const lastSeal = await tenantClient.auditCheckpoint.findFirst({
      orderBy: { seq: 'desc' },
    });
    const sealedHead = new Map(
      ((lastSeal?.partitionHeads ?? []) as unknown as PartitionHead[]).map(
        (h) => [h.partition, Number(h.seq)],
      ),
    );
    const ranges = (
      await tenantClient.$queryRaw<
        { partition: number; cutoffSeq: number; oldest: Date; newest: Date }[]
      >`
        SELECT "partition", MAX("partitionSeq") AS "cutoffSeq",
               MIN("timestamp") AS "oldest", MAX("timestamp") AS "newest"
        FROM "audit_events"
        WHERE "timestamp" < ${cutoff}
        GROUP BY "partition"
        ORDER BY "partition"
      `
    )
      .map((r) => ({
        ...r,
        cutoffSeq: Math.min(
          Number(r.cutoffSeq),
          sealedHead.get(r.partition) ?? 0,
        ),
      }))
      .filter((r) => r.cutoffSeq > 0);

    if (ranges.length === 0) {
      this.logger.log(
        `Retention run for tenant "${input.tenantId}": no AuditEvent rows older than ${input.retentionWindowMs}ms — nothing to prune`,
      );
      return {
        prunedCount: 0,
        anchorHash: null,
        anchors: [],
        retentionEventId: null,
      };
    }

    const anchors: {
      partition: number;
      anchorHash: string;
      eventsPrunedCount: number;
    }[] = [];
    for (const r of ranges) {
      const where = {
        partition: r.partition,
        partitionSeq: { lte: Number(r.cutoffSeq) },
      };
      const [last, count] = await Promise.all([
        tenantClient.auditEvent.findUniqueOrThrow({
          where: {
            partition_partitionSeq: {
              partition: r.partition,
              partitionSeq: Number(r.cutoffSeq),
            },
          },
          select: { eventHash: true },
        }),
        tenantClient.auditEvent.count({ where }),
      ]);
      anchors.push({
        partition: r.partition,
        anchorHash: last.eventHash,
        eventsPrunedCount: count,
      });
    }
    const prunedCount = anchors.reduce((n, a) => n + a.eventsPrunedCount, 0);
    const signatures = await Promise.all(
      anchors.map((a) =>
        this.signer.sign(
          input.tenantId,
          anchorDigestOf({ tenantId: input.tenantId, ...a }),
        ),
      ),
    );

    await tenantClient.$transaction([
      tenantClient.auditChainAnchor.createMany({
        data: anchors.map((a, i) => ({
          tenantId: input.tenantId,
          ...a,
          signature: signatures[i]!,
        })),
      }),
      tenantClient.auditEvent.deleteMany({
        where: {
          OR: ranges.map((r) => ({
            partition: r.partition,
            partitionSeq: { lte: Number(r.cutoffSeq) },
          })),
        },
      }),
    ]);

    // Kept for readers of the single-chain result: the last anchor written.
    const anchorHash = anchors[anchors.length - 1]!.anchorHash;
    const retentionEvent = await this.auditService.record(
      tenantClient,
      input.tenantId,
      {
        eventType: AUDIT_EVENT_TYPES.AUDIT_RETENTION_EXECUTED,
        actor: { type: 'system', id: 'system:audit-retention-workflow' },
        data: {
          eventsPrunedCount: prunedCount,
          anchorHash,
          anchors,
          retentionWindowMs: input.retentionWindowMs,
          prunedWindowStart: new Date(
            Math.min(...ranges.map((r) => new Date(r.oldest).getTime())),
          ).toISOString(),
          prunedWindowEnd: new Date(
            Math.max(...ranges.map((r) => new Date(r.newest).getTime())),
          ).toISOString(),
        },
      },
    );

    this.logger.log(
      `Retention run for tenant "${input.tenantId}": pruned ${prunedCount} AuditEvent row(s) across ${anchors.length} partition(s), recorded "${retentionEvent.id}"`,
    );

    return {
      prunedCount,
      anchorHash,
      anchors: anchors.map(({ partition, anchorHash: hash }) => ({
        partition,
        anchorHash: hash,
      })),
      retentionEventId: retentionEvent.id,
    };
  }
}
