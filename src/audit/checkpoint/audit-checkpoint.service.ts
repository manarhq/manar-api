import { Injectable } from '@nestjs/common';
import type {
  AuditCheckpoint,
  Prisma,
  PrismaClient as TenantPrismaClient,
} from '../../generated/tenant-client/client';
import { merkleRoot } from '../merkle';
import {
  checkpointHashOf,
  type PartitionHead,
  type PartitionRoot,
} from './checkpoint-format';
import { CheckpointSigner } from './checkpoint-signer';

export type { PartitionHead, PartitionRoot } from './checkpoint-format';
export { checkpointHashOf } from './checkpoint-format';

/**
 * Builds SEALs: every call that finds new audit events writes one
 * `AuditCheckpoint` holding, per advanced partition, the RFC 6962 root of
 * the events since the previous checkpoint, linked to that checkpoint and
 * signed with the tenant's key. Only one writer at a time per tenant
 * database (transaction-scoped advisory lock); a concurrent caller gets
 * `null` rather than waiting.
 */
@Injectable()
export class AuditCheckpointService {
  /**
   * At most this many events per partition go into one SEAL, so a long
   * backlog (the first SEAL after the upgrade covers all existing history)
   * is sealed over several rounds instead of one unbounded in-memory tree.
   */
  static MAX_RANGE = 50_000;

  constructor(private readonly signer: CheckpointSigner) {}

  async createCheckpoint(
    tenantClient: TenantPrismaClient,
    tenantId: string,
  ): Promise<AuditCheckpoint | null> {
    return tenantClient.$transaction(
      async (tx) => {
        const [lock] = await tx.$queryRaw<{ locked: boolean }[]>`
          SELECT pg_try_advisory_xact_lock(hashtext('manar.audit.checkpoint')) AS locked
        `;
        if (!lock?.locked) return null;
        return this.build(tx, tenantId);
      },
      { timeout: 30_000 },
    );
  }

  private async build(
    tx: Prisma.TransactionClient,
    tenantId: string,
  ): Promise<AuditCheckpoint | null> {
    const previous = await tx.auditCheckpoint.findFirst({
      orderBy: { seq: 'desc' },
    });
    const sealedUpTo = new Map(
      ((previous?.partitionHeads ?? []) as unknown as PartitionHead[]).map(
        (h) => [h.partition, Number(h.seq)],
      ),
    );
    const states = (await tx.auditPartitionState.findMany({
      where: { latestSeq: { gt: 0 } },
      orderBy: { partition: 'asc' },
    })) as {
      partition: number;
      latestSeq: number;
      latestEventHash: string | null;
    }[];

    // Heads are what is sealed: carried over from the previous SEAL, and
    // moved to the end of each range sealed now.
    const heads = new Map(
      ((previous?.partitionHeads ?? []) as unknown as PartitionHead[]).map(
        (h) => [h.partition, h],
      ),
    );
    const roots: PartitionRoot[] = [];
    for (const state of states) {
      let from = (sealedUpTo.get(state.partition) ?? 0) + 1;
      if (state.latestSeq < from) continue;
      // Skip a gap retention left: start at the first surviving event.
      const first = await tx.auditEvent.findFirst({
        where: {
          partition: state.partition,
          partitionSeq: { gte: from, lte: state.latestSeq },
        },
        orderBy: { partitionSeq: 'asc' },
        select: { partitionSeq: true },
      });
      if (!first) continue;
      from = first.partitionSeq;
      const to = Math.min(
        state.latestSeq,
        from + AuditCheckpointService.MAX_RANGE - 1,
      );
      const events = await tx.auditEvent.findMany({
        where: {
          partition: state.partition,
          partitionSeq: { gte: from, lte: to },
        },
        orderBy: { partitionSeq: 'asc' },
        select: { eventHash: true, partitionSeq: true },
      });
      if (events.length === 0) continue; // range already pruned by retention
      roots.push({
        partition: state.partition,
        fromSeq: from.toString(),
        toSeq: to.toString(),
        root: merkleRoot(events.map((e) => e.eventHash)),
      });
      const last = events[events.length - 1]!;
      heads.set(state.partition, {
        partition: state.partition,
        seq: last.partitionSeq.toString(),
        eventHash: last.eventHash,
      });
    }
    if (roots.length === 0) return null;

    const partitionHeads: PartitionHead[] = [...heads.values()].sort(
      (a, b) => a.partition - b.partition,
    );
    const seq = (previous?.seq ?? 0n) + 1n;
    const createdAt = new Date();
    const previousCheckpointHash = previous?.checkpointHash ?? null;
    const checkpointHash = checkpointHashOf({
      seq,
      createdAt,
      partitionHeads,
      roots,
      previousCheckpointHash,
    });
    // Sign first: signing creates the tenant key on the very first SEAL.
    const signature = await this.signer.sign(tenantId, checkpointHash);
    const { keyId } = await this.signer.publicKey(tenantId);

    const checkpoint = await tx.auditCheckpoint.create({
      data: {
        seq,
        createdAt,
        partitionHeads: partitionHeads as unknown as Prisma.InputJsonValue,
        roots: roots as unknown as Prisma.InputJsonValue,
        previousCheckpointHash,
        checkpointHash,
        signature,
        keyId,
      },
    });
    await tx.auditCheckpointRange.createMany({
      data: roots.map((r) => ({
        partition: r.partition,
        fromSeq: Number(r.fromSeq),
        toSeq: Number(r.toSeq),
        checkpointSeq: seq,
        root: r.root,
      })),
    });
    return checkpoint;
  }
}
