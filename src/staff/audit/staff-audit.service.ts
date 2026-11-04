import { createHash, randomUUID } from 'node:crypto';
import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { canonicalize } from '../../audit/canonical-json';
import { CheckpointSigner } from '../../audit/checkpoint/checkpoint-signer';
import { ControlPrismaService } from '../../database/control-prisma.service';
import type { Prisma } from '../../generated/control-client/client';
import { OpenBaoKvClient } from '../../openbao/openbao-kv.client';

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

/** Every stored column except `hash` itself. */
export interface HashedRow {
  seq: string;
  id: string;
  at: string;
  staffId: string | null;
  action: string;
  targetType: string | null;
  targetId: string | null;
  data: unknown;
  ip: string | null;
  requestId: string | null;
  previousHash: string | null;
}

/** sha256 over the canonical JSON of every stored column (domain-separated), hex. */
export function staffAuditHash(row: HashedRow): string {
  return createHash('sha256')
    .update(canonicalize({ domain: 'manar.staff_audit.row.v1', ...row }))
    .digest('hex');
}

export function staffCheckpointHash(c: {
  seq: bigint;
  createdAt: Date;
  headSeq: bigint;
  headHash: string;
  previousCheckpointHash: string | null;
}): string {
  return createHash('sha256')
    .update(
      canonicalize({
        domain: 'manar.staff_audit.checkpoint.v1',
        seq: c.seq.toString(),
        createdAt: c.createdAt.toISOString(),
        headSeq: c.headSeq.toString(),
        headHash: c.headHash,
        previousCheckpointHash: c.previousCheckpointHash,
      }),
    )
    .digest('hex');
}

export const STAFF_AUDIT_CHAIN_ID = Symbol('STAFF_AUDIT_CHAIN_ID');
const LOCK_KEY = 'staff_audit_events';
const ANCHOR_LOCK_KEY = 'staff_audit_anchor';
const VERIFY_BATCH = 1000;

export type StaffAuditVerdict =
  | { valid: true; count: number; checkpoints: number }
  | { valid: false; brokenAtSeq?: string; reason: string };

/**
 * The staff side's own hash chain (DESK spec §11.5): every staff call that reads customer data or
 * changes anything. Append-only; one global sequence under a transaction-scoped advisory lock.
 * Pass the caller's transaction so the audited change and its row commit together.
 *
 * The head is anchored outside the table: `checkpoint()` signs (seq, hash) with the Ed25519 key
 * CheckpointSigner keeps in OpenBao under this chain's id, stores the checkpoint, then names it in
 * OpenBao KV. `verify()` fails when a checkpoint's row is missing or differs (truncation, deleted
 * tail, rewritten chain), when the newest checkpoint OpenBao names is gone, or when the signing key
 * exists but no checkpoint does.
 */
@Injectable()
export class StaffAuditService {
  private readonly logger = new Logger(StaffAuditService.name);
  /** How long the anchor may name the checkpoint before the newest one. */
  static ANCHOR_LAG_MS = 120_000;

  constructor(
    private readonly control: ControlPrismaService,
    private readonly signer: CheckpointSigner,
    private readonly kv: OpenBaoKvClient,
    @Optional()
    @Inject(STAFF_AUDIT_CHAIN_ID)
    private readonly chainId: string = 'staff-audit',
  ) {}

  private get headPath(): string {
    return `audit/staff-audit-head/${this.chainId}`;
  }

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
    const row = {
      seq: (last?.seq ?? 0n) + 1n,
      id: randomUUID(),
      at: new Date(),
      staffId: input.staffId,
      action: input.action,
      targetType: input.targetType ?? null,
      targetId: input.targetId ?? null,
      data: (input.data ?? {}) as Prisma.InputJsonValue,
      ip: input.ip ?? null,
      requestId: input.requestId ?? null,
      previousHash: last?.hash ?? null,
    };
    const hash = staffAuditHash(hashed(row));
    await tx.staffAuditEvent.create({ data: { ...row, hash } });
    return { seq: row.seq, hash };
  }

  /**
   * Signs the current head if it moved since the last checkpoint, then names it in OpenBao.
   * Called every minute by the scheduler and right after each high-risk staff action.
   *
   * Serialised end to end: an outer transaction holds the anchor lock while a second one creates
   * and commits the checkpoint and the anchor is written, so checkpoints and anchor writes happen
   * in one order. The anchor only moves forward (`anchor()`), with KV check-and-set. Throws if
   * signing or the anchor write fails, so the caller can alert; the next call repairs the anchor.
   */
  async checkpoint(): Promise<{ seq: bigint } | null> {
    return this.control.$transaction(
      async (outer) => {
        await outer.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${ANCHOR_LOCK_KEY}))`;
        const cp = await this.control.$transaction(async (tx) => {
          await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${LOCK_KEY}))`;
          const head = await tx.staffAuditEvent.findFirst({
            orderBy: { seq: 'desc' },
            select: { seq: true, hash: true },
          });
          const prev = await tx.staffAuditCheckpoint.findFirst({
            orderBy: { seq: 'desc' },
          });
          if (!head || (prev && prev.headSeq === head.seq)) return prev ?? null;
          const content = {
            seq: (prev?.seq ?? 0n) + 1n,
            createdAt: new Date(),
            headSeq: head.seq,
            headHash: head.hash,
            previousCheckpointHash: prev?.checkpointHash ?? null,
          };
          const checkpointHash = staffCheckpointHash(content);
          const signature = await this.signer.sign(
            this.chainId,
            checkpointHash,
          );
          const { keyId } = await this.signer.publicKey(this.chainId);
          return tx.staffAuditCheckpoint.create({
            data: { ...content, checkpointHash, signature, keyId },
          });
        });
        if (!cp) return null;
        await this.anchor(cp);
        return { seq: cp.seq };
      },
      { timeout: 30_000 },
    );
  }

  /**
   * Names `cp` in OpenBao if it is newer than what the anchor names. Returns false (and writes
   * nothing) for an older or equal checkpoint. Check-and-set on the KV version: a concurrent writer
   * makes this throw instead of silently overwriting.
   */
  async anchor(cp: { seq: bigint; checkpointHash: string }): Promise<boolean> {
    const current = await this.kv.readSecretVersioned(this.headPath);
    if (current && BigInt(String(current.data.checkpointSeq)) >= cp.seq)
      return false;
    await this.kv.writeSecretCas(
      this.headPath,
      { checkpointSeq: cp.seq.toString(), checkpointHash: cp.checkpointHash },
      current?.version ?? 0,
    );
    return true;
  }

  async verify(now: Date = new Date()): Promise<StaffAuditVerdict> {
    // 1. The rows: every link and every hash.
    const hashes = new Map<bigint, string>();
    let previous: string | null = null;
    let after = 0n;
    for (;;) {
      const rows = await this.control.staffAuditEvent.findMany({
        where: { seq: { gt: after } },
        orderBy: { seq: 'asc' },
        take: VERIFY_BATCH,
      });
      if (rows.length === 0) break;
      for (const r of rows) {
        const ok =
          r.seq === after + 1n &&
          r.previousHash === previous &&
          r.hash === staffAuditHash(hashed(r));
        if (!ok)
          return { valid: false, brokenAtSeq: r.seq.toString(), reason: 'row' };
        hashes.set(r.seq, r.hash);
        previous = r.hash;
        after = r.seq;
      }
    }

    // 2. The checkpoints: signed, linked, and each one's head row present with the same hash.
    const checkpoints = await this.control.staffAuditCheckpoint.findMany({
      orderBy: { seq: 'asc' },
    });
    const anchor = await this.kv.readSecretIfPresent(this.headPath);
    const hasKey = await this.signer.hasKey(this.chainId);
    if (checkpoints.length === 0)
      return anchor || hasKey
        ? { valid: false, reason: 'checkpoints_missing' }
        : { valid: true, count: hashes.size, checkpoints: 0 };
    const { publicKeyPem } = await this.signer.publicKey(this.chainId);
    let prevHash: string | null = null;
    let expectedSeq = 1n;
    for (const c of checkpoints) {
      const recomputed = staffCheckpointHash(c);
      if (
        c.seq !== expectedSeq ||
        c.previousCheckpointHash !== prevHash ||
        c.checkpointHash !== recomputed ||
        !CheckpointSigner.verify(recomputed, c.signature, publicKeyPem)
      )
        return { valid: false, reason: `checkpoint_${c.seq}_invalid` };
      if (hashes.get(c.headSeq) !== c.headHash)
        return {
          valid: false,
          brokenAtSeq: c.headSeq.toString(),
          reason: 'checkpointed_row_missing_or_changed',
        };
      prevHash = c.checkpointHash;
      expectedSeq = c.seq + 1n;
    }

    // 3. The anchor outside the database names the newest checkpoint. It may lag by one only while
    // that newest checkpoint is younger than ANCHOR_LAG_MS (written, anchor write in flight or
    // failed and not yet repaired). Ahead of the table, or any other lag, is a failure.
    if (!anchor) return { valid: false, reason: 'anchor_missing' };
    const anchoredSeq = BigInt(String(anchor.checkpointSeq));
    const named = checkpoints.find((c) => c.seq === anchoredSeq);
    if (!named || named.checkpointHash !== anchor.checkpointHash)
      return { valid: false, reason: 'anchored_checkpoint_missing' };
    const newest = checkpoints[checkpoints.length - 1]!;
    const lag = newest.seq - anchoredSeq;
    if (
      lag > 1n ||
      (lag === 1n &&
        now.getTime() - newest.createdAt.getTime() >
          StaffAuditService.ANCHOR_LAG_MS)
    )
      return { valid: false, reason: 'anchor_stale' };
    return { valid: true, count: hashes.size, checkpoints: checkpoints.length };
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

function hashed(r: {
  seq: bigint;
  id: string;
  at: Date;
  staffId: string | null;
  action: string;
  targetType: string | null;
  targetId: string | null;
  data: unknown;
  ip: string | null;
  requestId: string | null;
  previousHash: string | null;
}): HashedRow {
  return {
    seq: r.seq.toString(),
    id: r.id,
    at: r.at.toISOString(),
    staffId: r.staffId,
    action: r.action,
    targetType: r.targetType,
    targetId: r.targetId,
    data: r.data,
    ip: r.ip,
    requestId: r.requestId,
    previousHash: r.previousHash,
  };
}
