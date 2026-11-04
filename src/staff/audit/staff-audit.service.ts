import { createHash } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { canonicalize } from '../../audit/canonical-json';
import { ControlPrismaService } from '../../database/control-prisma.service';
import type { Prisma } from '../../generated/control-client/client';

export type StaffAuditTarget =
  | 'ACCOUNT'
  | 'TENANT'
  | 'STAFF'
  | 'ROLE'
  | 'GROUP'
  | 'CHANGE_REQUEST'
  | 'RESTRICTION'
  | 'APPEAL'
  | 'MATCH'
  | 'SEARCH'
  | 'ERROR';

export interface StaffAuditInput {
  /** null for the system (re-signup checks, expiry jobs). */
  staffId: string | null;
  action: string;
  targetType?: StaffAuditTarget;
  targetId?: string;
  data?: Record<string, unknown>;
  ip?: string;
  requestId?: string;
}

interface HashedRow {
  seq: string;
  at: string;
  staffId: string | null;
  action: string;
  targetType: string | null;
  targetId: string | null;
  data: unknown;
}

/** sha256(previousHash + canonical JSON of the row), hex. */
export function staffAuditHash(
  previousHash: string | null,
  row: HashedRow,
): string {
  return createHash('sha256')
    .update(previousHash ?? '')
    .update(canonicalize(row))
    .digest('hex');
}

const LOCK_KEY = 'staff_audit_events';
const VERIFY_BATCH = 1000;

/**
 * The staff side's own hash chain (DESK spec §11.5): every staff call that reads customer data or
 * changes anything. Append-only; one global sequence under a transaction-scoped advisory lock.
 * Pass the caller's transaction so the audited change and its row commit together.
 */
@Injectable()
export class StaffAuditService {
  constructor(private readonly control: ControlPrismaService) {}

  async append(
    input: StaffAuditInput,
    tx?: Prisma.TransactionClient,
  ): Promise<{ seq: bigint; hash: string }> {
    if (!tx)
      return this.control.$transaction((inner) => this.append(input, inner));
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${LOCK_KEY}))`;
    const last = await tx.staffAuditEvent.findFirst({
      orderBy: { seq: 'desc' },
      select: { seq: true, hash: true },
    });
    const seq = (last?.seq ?? 0n) + 1n;
    const at = new Date();
    const data = (input.data ?? {}) as Prisma.InputJsonValue;
    const hash = staffAuditHash(last?.hash ?? null, {
      seq: seq.toString(),
      at: at.toISOString(),
      staffId: input.staffId,
      action: input.action,
      targetType: input.targetType ?? null,
      targetId: input.targetId ?? null,
      data,
    });
    await tx.staffAuditEvent.create({
      data: {
        seq,
        at,
        staffId: input.staffId,
        action: input.action,
        targetType: input.targetType,
        targetId: input.targetId,
        data,
        ip: input.ip,
        requestId: input.requestId,
        previousHash: last?.hash ?? null,
        hash,
      },
    });
    return { seq, hash };
  }

  /** Walks the whole chain in batches; the first row whose link or hash does not hold breaks it. */
  async verify(): Promise<
    { valid: true; count: number } | { valid: false; brokenAtSeq: string }
  > {
    let previous: string | null = null;
    let after = 0n;
    let count = 0;
    for (;;) {
      const rows = await this.control.staffAuditEvent.findMany({
        where: { seq: { gt: after } },
        orderBy: { seq: 'asc' },
        take: VERIFY_BATCH,
      });
      if (rows.length === 0) return { valid: true, count };
      for (const r of rows) {
        const expected = staffAuditHash(previous, {
          seq: r.seq.toString(),
          at: r.at.toISOString(),
          staffId: r.staffId,
          action: r.action,
          targetType: r.targetType,
          targetId: r.targetId,
          data: r.data,
        });
        if (
          r.seq !== after + 1n ||
          r.previousHash !== previous ||
          r.hash !== expected
        )
          return { valid: false, brokenAtSeq: r.seq.toString() };
        previous = r.hash;
        after = r.seq;
        count++;
      }
    }
  }

  list(q: {
    before?: bigint;
    staffId?: string;
    targetId?: string;
    limit: number;
  }) {
    return this.control.staffAuditEvent.findMany({
      where: {
        ...(q.before ? { seq: { lt: q.before } } : {}),
        ...(q.staffId ? { staffId: q.staffId } : {}),
        ...(q.targetId ? { targetId: q.targetId } : {}),
      },
      orderBy: { seq: 'desc' },
      take: Math.min(q.limit, 200),
    });
  }
}
