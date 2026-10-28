import { Injectable } from '@nestjs/common';
import type { Prisma } from '../../generated/control-client/client';
import { ControlPrismaService } from '../../database/control-prisma.service';
import type { PartitionHead } from './checkpoint-format';

export interface SealMark {
  sealSeq: bigint;
  sealHash: string;
  verified: { seq: bigint; hash: string; heads: PartitionHead[] } | null;
}

/**
 * Each tenant's newest SEAL and verification watermark, kept in the control
 * database (`AuditSealMark`), outside the tenant database an attacker would
 * be rewriting.
 */
export interface SealMarkStore {
  get(tenantId: string): Promise<SealMark | null>;
  setSeal(tenantId: string, seq: bigint, hash: string): Promise<void>;
  setVerified(
    tenantId: string,
    verified: { seq: bigint; hash: string; heads: PartitionHead[] },
  ): Promise<void>;
}

export const SEAL_MARKS = Symbol('SEAL_MARKS');

/**
 * The tenant database no longer holds the SEAL the control database names
 * as newest: SEALs were deleted or replaced. The worker refuses to seal on
 * top of that (it would re-sign rewritten history).
 */
export class SealContinuityError extends Error {
  readonly code = 'seal_continuity_broken';
}

@Injectable()
export class ControlSealMarkStore implements SealMarkStore {
  constructor(private readonly control: ControlPrismaService) {}

  async get(tenantId: string): Promise<SealMark | null> {
    const row = await this.control.auditSealMark.findUnique({
      where: { tenantId },
    });
    if (!row) return null;
    return {
      sealSeq: row.sealSeq,
      sealHash: row.sealHash,
      verified:
        row.verifiedSeq !== null && row.verifiedHash !== null
          ? {
              seq: row.verifiedSeq,
              hash: row.verifiedHash,
              heads: (row.verifiedHeads ?? []) as unknown as PartitionHead[],
            }
          : null,
    };
  }

  async setSeal(tenantId: string, seq: bigint, hash: string): Promise<void> {
    // Only ever moves forward: a late write for an older SEAL is ignored.
    await this.control.$executeRaw`
      INSERT INTO "audit_seal_marks" ("tenantId", "sealSeq", "sealHash", "updatedAt")
      VALUES (${tenantId}, ${seq}, ${hash}, now())
      ON CONFLICT ("tenantId") DO UPDATE
        SET "sealSeq" = EXCLUDED."sealSeq", "sealHash" = EXCLUDED."sealHash", "updatedAt" = now()
        WHERE "audit_seal_marks"."sealSeq" < EXCLUDED."sealSeq"
    `;
  }

  async setVerified(
    tenantId: string,
    verified: { seq: bigint; hash: string; heads: PartitionHead[] },
  ): Promise<void> {
    await this.control.auditSealMark.updateMany({
      where: { tenantId },
      data: {
        verifiedSeq: verified.seq,
        verifiedHash: verified.hash,
        verifiedHeads: verified.heads as unknown as Prisma.InputJsonValue,
      },
    });
  }
}
