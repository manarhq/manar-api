import { Injectable } from '@nestjs/common';
import { Prisma } from '../generated/tenant-client/client';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';

/** Totals only. Nothing in here may ever carry a name, path, prompt, device or person. */
export interface ReportCardTotals {
  from: string;
  to: string;
  actions: number;
  askedYou: number;
  blocked: number;
  secretsKeptSafe: number;
  /** Actions per day, oldest first, 7 entries. */
  series: number[];
}

const DAY_MS = 86_400_000;
const CACHE_MS = 60 * 60 * 1000;
const ACTION_TYPES = [
  'authorization.allowed',
  'authorization.denied',
  'authorization.pending_approval',
];

@Injectable()
export class ReportCardService {
  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

  /** The 7 days ending at `end`, from one aggregate query over the tenant's own audit table. */
  async compute(
    client: TenantPrismaClient,
    end: Date = new Date(),
  ): Promise<ReportCardTotals> {
    const start = new Date(end.getTime() - 7 * DAY_MS);
    const rows = await client.$queryRaw<
      { d: number; t: string; n: number }[]
    >(Prisma.sql`
      SELECT d, t, count(*)::int AS n FROM (
        SELECT floor(extract(epoch FROM (${end}::timestamp - "timestamp")) / 86400)::int AS d,
          CASE WHEN ("eventType" = 'secret.touched' AND data->>'blocked' = 'true')
                 OR "eventType" = 'secret.vault.denied' THEN 'secret.safe'
               ELSE "eventType" END AS t
        FROM audit_events
        WHERE "timestamp" >= ${start}::timestamp AND "timestamp" < ${end}::timestamp
          AND "eventType" IN (${Prisma.join([...ACTION_TYPES, 'secret.touched', 'secret.vault.denied'])})
      ) x GROUP BY d, t`);
    const totals = { actions: 0, askedYou: 0, blocked: 0, secretsKeptSafe: 0 };
    const series = [0, 0, 0, 0, 0, 0, 0];
    for (const { d, t, n } of rows) {
      if (d < 0 || d > 6) continue;
      if (ACTION_TYPES.includes(t)) {
        totals.actions += n;
        series[6 - d]! += n;
      }
      if (t === 'authorization.pending_approval') totals.askedYou += n;
      if (t === 'authorization.denied') totals.blocked += n;
      if (t === 'secret.safe') totals.secretsKeptSafe += n;
    }
    return {
      from: start.toISOString(),
      to: new Date(end.getTime() - 1).toISOString(),
      ...totals,
      series,
    };
  }

  /** Stored card when under an hour old, else computed now and stored. */
  async cardFor(tenantId: string): Promise<ReportCardTotals> {
    const cached = await this.control.weeklyReportCard.findFirst({
      where: { tenantId },
      orderBy: { weekEnd: 'desc' },
    });
    if (cached && Date.now() - cached.computedAt.getTime() < CACHE_MS) {
      return cached.data as unknown as ReportCardTotals;
    }
    return this.refresh(tenantId);
  }

  async refresh(tenantId: string): Promise<ReportCardTotals> {
    const client = await this.tenantDatabaseManager.getClient(tenantId);
    const end = new Date();
    const data = await this.compute(client, end);
    // Keyed by the UTC day of `end`: a recompute on the same day replaces the row.
    const weekEnd = new Date(Math.floor(end.getTime() / DAY_MS) * DAY_MS);
    await this.control.weeklyReportCard.upsert({
      where: { tenantId_weekEnd: { tenantId, weekEnd } },
      create: {
        tenantId,
        weekEnd,
        data: data as unknown as Prisma.InputJsonValue,
      },
      update: {
        data: data as unknown as Prisma.InputJsonValue,
        computedAt: new Date(),
      },
    });
    return data;
  }
}
