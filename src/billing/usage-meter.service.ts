import { randomUUID } from 'node:crypto';
import {
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ControlPrismaService } from '../database/control-prisma.service';
import type { Prisma } from '../generated/control-client/client';
import { EntitlementsService, type Entitlement } from './entitlements.service';
import {
  COMPANY_DEFAULT_CAP_CREDITS,
  ACTIVE_DAYS,
  COMPANY_MIN_SEATS,
  PRO_DEFAULT_CAP_CREDITS,
  SEAT_PLANS,
  TOP_UP_BELOW_CREDITS,
  WALLET_PLANS,
  monthOf,
} from './plans';

export type UsageKind = 'ai' | 'cloud_minute';

export type PausedReason =
  | 'paid_features_paused'
  | 'allowance_used'
  | 'spend_cap_reached'
  | 'credits_exhausted';

/** 402: a paid extra is paused. Protection is not affected (it never reaches the meter). */
export class UsagePausedError extends HttpException {
  constructor(
    readonly reason: PausedReason,
    upgradeUrl: string,
  ) {
    super(
      {
        statusCode: HttpStatus.PAYMENT_REQUIRED,
        code: reason,
        message:
          'Paused: add credits or raise your cap. Protection is still on.',
        upgradeUrl,
      },
      HttpStatus.PAYMENT_REQUIRED,
    );
  }
}

export interface ConsumeResult {
  /** `allowance`, `credits`, or `duplicate` (already counted under this key). */
  source: 'allowance' | 'credits' | 'duplicate';
  /** Credits left after this use (only computed when a credit was spent). */
  balance?: number;
}

type Tx = Prisma.TransactionClient;

/** Default cap for a plan when the wallet has no row yet. */
export function defaultCap(plan: Entitlement['plan']): number | null {
  if (plan === 'pro') return PRO_DEFAULT_CAP_CREDITS;
  if (SEAT_PLANS.has(plan)) return COMPANY_DEFAULT_CAP_CREDITS;
  return null;
}

/** The month's allowance for one kind; Company pools it over max(3, committed, seats seen). */
export function allowanceFor(
  e: Entitlement,
  kind: UsageKind,
  seats: number,
): number {
  const per = kind === 'ai' ? e.allowance.ai : e.allowance.cloudMinutes;
  if (!SEAT_PLANS.has(e.plan)) return per;
  return per * Math.max(COMPANY_MIN_SEATS, e.committedSeats ?? 0, seats);
}

/**
 * Meters the paid extras: AI actions and cloud-agent minutes (workspace spec 2026-11-04-payg,
 * section 5). Safety never calls this: blocks, approvals, vault and audit are not metered, and
 * `decision-path-dependencies.spec.ts` keeps it off those paths.
 *
 * Every use is one control-DB transaction under a per-tenant advisory lock: the allowance first,
 * then credits (oldest expiry first) within the monthly cap. A refusal writes nothing. Any error
 * here refuses the paid extra (503 `metering_unavailable`): failing closed costs an answer, never
 * protection.
 */
@Injectable()
export class UsageMeterService {
  private readonly logger = new Logger(UsageMeterService.name);
  /** Called after a credit was spent and the balance is low (auto top-up). Set by the HTTP module. */
  onLowBalance?: (tenantId: string) => void;

  constructor(
    private readonly control: ControlPrismaService,
    private readonly entitlements: EntitlementsService,
  ) {}

  async consume(
    tenantId: string,
    kind: UsageKind,
    key: string,
    now = new Date(),
  ): Promise<ConsumeResult> {
    let result: ConsumeResult;
    try {
      const e = await this.entitlements.get(tenantId);
      result = await this.control.$transaction((tx) =>
        this.consumeLocked(tx, e, tenantId, kind, key, now),
      );
    } catch (error) {
      if (error instanceof UsagePausedError) throw error;
      this.logger.error(
        `metering failed for tenant "${tenantId}": ${String(error)}`,
      );
      throw new ServiceUnavailableException({
        statusCode: 503,
        code: 'metering_unavailable',
      });
    }
    if (
      result.source === 'credits' &&
      (result.balance ?? 0) < TOP_UP_BELOW_CREDITS
    )
      this.onLowBalance?.(tenantId);
    return result;
  }

  private async consumeLocked(
    tx: Tx,
    e: Entitlement,
    tenantId: string,
    kind: UsageKind,
    key: string,
    now: Date,
  ): Promise<ConsumeResult> {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`wallet:${tenantId}`}))`;
    const seen = await tx.usageEvent.findUnique({
      where: { tenantId_key: { tenantId, key } },
    });
    if (seen) return { source: 'duplicate' };
    const upgradeUrl = this.entitlements.upgradeUrl();
    if (e.status === 'frozen' || e.status === 'read_only')
      throw new UsagePausedError('paid_features_paused', upgradeUrl);

    const month = monthOf(now);
    const m = await tx.usageMonth.upsert({
      where: { tenantId_month: { tenantId, month } },
      create: { tenantId, month },
      update: {},
    });
    const used = kind === 'ai' ? m.aiUsed : m.minutesUsed;
    const seats = SEAT_PLANS.has(e.plan)
      ? await this.seatsSeen(tx, tenantId, month)
      : 0;
    const counter = kind === 'ai' ? 'aiUsed' : 'minutesUsed';

    if (used < allowanceFor(e, kind, seats)) {
      await tx.usageMonth.update({
        where: { tenantId_month: { tenantId, month } },
        data: { [counter]: { increment: 1 } },
      });
      await tx.usageEvent.create({
        data: { tenantId, key, kind, source: 'allowance' },
      });
      return { source: 'allowance' };
    }

    if (!WALLET_PLANS.has(e.plan))
      throw new UsagePausedError('allowance_used', upgradeUrl);
    const wallet = await tx.creditWallet.findUnique({ where: { tenantId } });
    const cap = wallet ? wallet.capCredits : defaultCap(e.plan);
    if (cap !== null && m.creditsSpent + 1 > cap)
      throw new UsagePausedError('spend_cap_reached', upgradeUrl);
    const lot = await tx.creditLot.findFirst({
      where: { tenantId, remaining: { gt: 0 }, expiresAt: { gt: now } },
      orderBy: [{ expiresAt: 'asc' }, { createdAt: 'asc' }],
    });
    if (!lot) throw new UsagePausedError('credits_exhausted', upgradeUrl);
    await tx.creditLot.update({
      where: { id: lot.id },
      data: { remaining: { decrement: 1 } },
    });
    await tx.usageMonth.update({
      where: { tenantId_month: { tenantId, month } },
      data: { [counter]: { increment: 1 }, creditsSpent: { increment: 1 } },
    });
    await tx.usageEvent.create({
      data: { tenantId, key, kind, source: 'credits', lotId: lot.id },
    });
    return { source: 'credits', balance: await balanceOf(tx, tenantId, now) };
  }

  /**
   * One AI action around `fn`: metered before the model is called, given back if `fn` throws or
   * answers `available: false`. The key is always made here: a client-chosen key would let a
   * repeated key read as "already counted" and get answers for free.
   */
  async ai<T>(tenantId: string, fn: () => Promise<T>): Promise<T> {
    const key = `ai:${randomUUID()}`;
    await this.consume(tenantId, 'ai', key);
    let result: T;
    try {
      result = await fn();
    } catch (error) {
      await this.release(tenantId, key);
      throw error;
    }
    if ((result as { available?: boolean } | null)?.available === false)
      await this.release(tenantId, key);
    return result;
  }

  /**
   * Gives a use back when no answer came (the model was unavailable): the event goes, the
   * counters go down, a spent credit returns to its lot. Never throws (best effort).
   */
  async release(tenantId: string, key: string): Promise<void> {
    try {
      await this.control.$transaction(async (tx) => {
        await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`wallet:${tenantId}`}))`;
        const ev = await tx.usageEvent.findUnique({
          where: { tenantId_key: { tenantId, key } },
        });
        if (!ev) return;
        await tx.usageEvent.delete({
          where: { tenantId_key: { tenantId, key } },
        });
        const month = monthOf(ev.createdAt);
        const counter = ev.kind === 'ai' ? 'aiUsed' : 'minutesUsed';
        await tx.usageMonth.updateMany({
          where: { tenantId, month },
          data: {
            [counter]: { decrement: 1 },
            ...(ev.source === 'credits'
              ? { creditsSpent: { decrement: 1 } }
              : {}),
          },
        });
        if (ev.lotId)
          await tx.creditLot.updateMany({
            where: { id: ev.lotId, tenantId },
            data: { remaining: { increment: 1 } },
          });
      });
    } catch (error) {
      this.logger.warn(
        `usage release failed for "${tenantId}": ${String(error)}`,
      );
    }
  }

  /** Active seats so far this month, or last month's if higher (the pool must not shrink on the 1st). */
  private async seatsSeen(
    tx: Tx,
    tenantId: string,
    month: string,
  ): Promise<number> {
    const [y, mo] = month.split('-').map(Number) as [number, number];
    const prev = monthOf(new Date(Date.UTC(y, mo - 2, 1)));
    const rows = await tx.$queryRaw<{ n: bigint }[]>`
      SELECT COUNT(*)::bigint AS n FROM (
        SELECT to_char("day", 'YYYY-MM') AS m, "subjectId" FROM "active_days"
        WHERE "tenantId" = ${tenantId} AND "kind" = 'seat'
          AND to_char("day", 'YYYY-MM') IN (${month}, ${prev})
        GROUP BY 1, 2
        HAVING COUNT(*) >= ${ACTIVE_DAYS}
      ) s GROUP BY m`;
    return Math.max(0, ...rows.map((r) => Number(r.n)));
  }
}

/** Credits left: the unexpired remainder of every lot. */
export async function balanceOf(
  db: Pick<Tx, 'creditLot'>,
  tenantId: string,
  now = new Date(),
): Promise<number> {
  const agg = await db.creditLot.aggregate({
    where: { tenantId, expiresAt: { gt: now } },
    _sum: { remaining: true },
  });
  return agg._sum.remaining ?? 0;
}
