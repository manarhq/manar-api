import { Injectable, Logger } from '@nestjs/common';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { dayOf, meterTarget } from './meter-targets';
import { ACTIVE_DAYS, monthOf, type PlanName } from './plans';
import { StripeGateway } from './stripe.gateway';

/** Look back far enough that a worker gap under a day loses no active day. */
const LOOKBACK_MS = 26 * 3_600_000;
const FLUSH_BATCH = 500;

/**
 * The hourly billing tick (workspace spec 2026-11-04-payg, 4.2 and 6): marks today's active
 * devices and seats, queues the meter units that became billable, and sends the queue to Stripe.
 * Every step is idempotent: days are a primary key, a report's identifier is its target, and a
 * report is marked sent only after Stripe accepted it. Stripe being down only leaves the queue.
 */
@Injectable()
export class BillingTickService {
  private readonly logger = new Logger(BillingTickService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly stripe: StripeGateway,
  ) {}

  async run(now = new Date()): Promise<{
    tenants: number;
    queued: number;
    sent: number;
    failed: number;
  }> {
    const rows = await this.control.tenantEntitlement.findMany({
      where: { plan: { in: ['pro', 'company', 'company_trial'] } },
      select: {
        tenantId: true,
        plan: true,
        status: true,
        committedSeats: true,
        stripeSubscriptionId: true,
      },
    });
    let queued = 0;
    for (const r of rows) {
      try {
        await this.markActiveDays(r.tenantId, now);
        // Only a live subscription is billed; a trial counts days for its pool only.
        if (r.stripeSubscriptionId && r.status !== 'frozen')
          queued += await this.queueReports(
            r.tenantId,
            r.plan,
            r.committedSeats,
            now,
          );
      } catch (error) {
        this.logger.error(
          `billing tick failed for tenant "${r.tenantId}": ${String(error)}`,
        );
      }
    }
    const { sent, failed } = this.stripe.configured
      ? await this.flush()
      : { sent: 0, failed: 0 };
    return { tenants: rows.length, queued, sent, failed };
  }

  /** Records the UTC day of each recent sign-in and device check-in. */
  async markActiveDays(tenantId: string, now = new Date()): Promise<void> {
    const db = await this.tenants.getClient(tenantId);
    const since = new Date(now.getTime() - LOOKBACK_MS);
    const [hosts, people] = await Promise.all([
      db.host.findMany({
        where: { status: 'APPROVED', lastSeenAt: { gte: since } },
        select: { id: true, ownerSubject: true, lastSeenAt: true },
      }),
      db.userProfile.findMany({
        where: { lastSeenAt: { gte: since } },
        select: { keycloakSubject: true, lastSeenAt: true },
      }),
    ]);
    const data = [
      ...hosts.map((h) => ({
        tenantId,
        kind: 'device',
        subjectId: h.id,
        day: dayOf(h.lastSeenAt!),
      })),
      // A seat is active on the days its person signed in or one of their devices checked in.
      ...hosts
        .filter((h) => h.ownerSubject)
        .map((h) => ({
          tenantId,
          kind: 'seat',
          subjectId: h.ownerSubject!,
          day: dayOf(h.lastSeenAt!),
        })),
      ...people.map((p) => ({
        tenantId,
        kind: 'seat',
        subjectId: p.keycloakSubject,
        day: dayOf(p.lastSeenAt),
      })),
    ];
    if (data.length)
      await this.control.activeDay.createMany({ data, skipDuplicates: true });
  }

  /** Active devices or seats in a month: 3 or more active days. */
  async activeCount(
    tenantId: string,
    kind: 'device' | 'seat',
    month: string,
  ): Promise<number> {
    const rows = await this.control.$queryRaw<{ n: bigint }[]>`
      SELECT COUNT(*)::bigint AS n FROM (
        SELECT "subjectId" FROM "active_days"
        WHERE "tenantId" = ${tenantId} AND "kind" = ${kind}
          AND to_char("day", 'YYYY-MM') = ${month}
        GROUP BY "subjectId" HAVING COUNT(*) >= ${ACTIVE_DAYS}
      ) s`;
    return Number(rows[0]?.n ?? 0);
  }

  /**
   * Queues what became billable this month, and last month's late activations if last month was
   * already being billed (so a new subscriber is never billed for the month before it).
   */
  async queueReports(
    tenantId: string,
    plan: PlanName,
    committedSeats: number | null,
    now = new Date(),
  ): Promise<number> {
    const current = monthOf(now);
    const previous = monthOf(
      new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1)),
    );
    let queued = 0;
    for (const month of [previous, current]) {
      const kind = plan === 'pro' ? 'device' : 'seat';
      const goal = meterTarget(
        plan,
        await this.activeCount(tenantId, kind, month),
        committedSeats,
      );
      if (!goal) continue;
      const agg = await this.control.meterReport.aggregate({
        where: { tenantId, meter: goal.meter, month },
        _sum: { value: true },
        _count: true,
      });
      if (month === previous && agg._count === 0) continue;
      const delta = goal.target - (agg._sum.value ?? 0);
      if (delta <= 0) continue;
      const r = await this.control.meterReport.createMany({
        data: [
          {
            identifier: `${tenantId}:${goal.meter}:${month}:${goal.target}`,
            tenantId,
            meter: goal.meter,
            month,
            value: delta,
          },
        ],
        skipDuplicates: true,
      });
      queued += r.count;
    }
    return queued;
  }

  /**
   * Sends queued reports, oldest first. Stripe unreachable (5xx, network) stops the round: the rest
   * wait. An identifier Stripe already has means an earlier send landed before we marked it: sent.
   * Any other refusal (4xx) skips only that report, so one bad row cannot hold up the queue.
   */
  async flush(): Promise<{ sent: number; failed: number }> {
    const queue = await this.control.meterReport.findMany({
      where: { reportedAt: null },
      orderBy: { createdAt: 'asc' },
      take: FLUSH_BATCH,
    });
    if (!queue.length) return { sent: 0, failed: 0 };
    const customers = new Map(
      (
        await this.control.tenantEntitlement.findMany({
          where: {
            tenantId: { in: [...new Set(queue.map((q) => q.tenantId))] },
          },
          select: { tenantId: true, stripeCustomerId: true },
        })
      ).map((e) => [e.tenantId, e.stripeCustomerId]),
    );
    let sent = 0;
    let failed = 0;
    for (const q of queue) {
      const customer = customers.get(q.tenantId);
      if (!customer) continue;
      try {
        await this.stripe.meterEvent({
          meter: q.meter as never,
          customer,
          value: q.value,
          identifier: q.identifier,
        });
      } catch (error) {
        const e = error as { statusCode?: number; message?: string };
        const landed = /already exists with identifier/i.test(e.message ?? '');
        if (!landed) {
          failed++;
          this.logger.warn(
            `meter report ${q.identifier} not sent, queued: ${String(error)}`,
          );
          const refused =
            !!e.statusCode && e.statusCode >= 400 && e.statusCode < 500;
          if (refused) continue;
          return { sent, failed };
        }
      }
      await this.control.meterReport.update({
        where: { identifier: q.identifier },
        data: { reportedAt: new Date() },
      });
      sent++;
    }
    return { sent, failed };
  }
}
