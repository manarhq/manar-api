import { Injectable } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../../generated/tenant-client/client';
import { inclusionProof, type MerkleProofStep } from '../merkle';
import type { PartitionHead, PartitionRoot } from './checkpoint-format';

export class AuditEventNotFoundError extends Error {
  readonly code = 'audit_event_not_found';
}

/** The event exists but no SEAL covers it yet (they are written every second). */
export class AuditEventNotCheckpointedError extends Error {
  readonly code = 'audit_event_not_checkpointed';
  readonly retryAfterMs = 1000;
}

export interface SealedCheckpoint {
  seq: string;
  createdAt: string;
  partitionHeads: PartitionHead[];
  roots: PartitionRoot[];
  previousCheckpointHash: string | null;
  checkpointHash: string;
  signature: string;
  keyId: string;
}

/**
 * Everything a recipient needs to check one event without trusting Manar:
 * hash the leaf up the proof to `root`, find `root` in `checkpoint.roots`,
 * and verify `checkpoint.signature` over `checkpoint.checkpointHash` with
 * the tenant's public key (`GET /audit/checkpoints/public-key`).
 */
export interface AuditEventProof {
  eventId: string;
  partition: number;
  partitionSeq: string;
  leaf: string;
  proof: MerkleProofStep[];
  root: string;
  checkpoint: SealedCheckpoint;
}

interface CheckpointRow {
  seq: bigint;
  createdAt: Date;
  partitionHeads: PartitionHead[];
  roots: PartitionRoot[];
  previousCheckpointHash: string | null;
  checkpointHash: string;
  signature: string;
  keyId: string;
}

@Injectable()
export class AuditProofService {
  async proveEvent(
    tenantClient: TenantPrismaClient,
    eventId: string,
  ): Promise<AuditEventProof> {
    const event = await tenantClient.auditEvent.findUnique({
      where: { id: eventId },
    });
    if (!event) {
      throw new AuditEventNotFoundError(
        `AuditEvent "${eventId}" was not found`,
      );
    }

    const [checkpoint] = await tenantClient.$queryRaw<CheckpointRow[]>`
      SELECT c.* FROM "audit_checkpoints" c
      WHERE EXISTS (
        SELECT 1 FROM jsonb_array_elements(c."roots") r
        WHERE (r->>'partition')::int = ${event.partition}
          AND (r->>'fromSeq')::bigint <= ${event.partitionSeq}
          AND (r->>'toSeq')::bigint >= ${event.partitionSeq}
      )
      ORDER BY c."seq"
      LIMIT 1
    `;
    if (!checkpoint) {
      throw new AuditEventNotCheckpointedError(
        `AuditEvent "${eventId}" is not covered by a checkpoint yet`,
      );
    }
    const range = checkpoint.roots.find(
      (r) =>
        r.partition === event.partition &&
        BigInt(r.fromSeq) <= event.partitionSeq &&
        BigInt(r.toSeq) >= event.partitionSeq,
    )!;
    const events = await tenantClient.auditEvent.findMany({
      where: {
        partition: event.partition,
        partitionSeq: { gte: BigInt(range.fromSeq), lte: BigInt(range.toSeq) },
      },
      orderBy: { partitionSeq: 'asc' },
      select: { id: true, eventHash: true },
    });
    const index = events.findIndex((e) => e.id === event.id);

    return {
      eventId: event.id,
      partition: event.partition,
      partitionSeq: event.partitionSeq.toString(),
      leaf: event.eventHash,
      proof: inclusionProof(
        events.map((e) => e.eventHash),
        index,
      ),
      // The signed root, not one recomputed here: a tampered store then fails
      // the recipient's check instead of producing a self-consistent proof.
      root: range.root,
      checkpoint: {
        seq: checkpoint.seq.toString(),
        createdAt: checkpoint.createdAt.toISOString(),
        partitionHeads: checkpoint.partitionHeads,
        roots: checkpoint.roots,
        previousCheckpointHash: checkpoint.previousCheckpointHash,
        checkpointHash: checkpoint.checkpointHash,
        signature: checkpoint.signature,
        keyId: checkpoint.keyId,
      },
    };
  }
}
