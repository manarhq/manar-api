import { Injectable, Logger } from '@nestjs/common';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { setFrictionOverBudget } from '../metrics/metrics';
import {
  FRICTION_BUDGET,
  dayKey,
  dayRange,
  numbers,
  overBudget,
  promptsPerDeveloperPerDay,
  type FrictionNumbers,
  type FrictionRow,
} from './friction';

const UNASSIGNED = '_unassigned';
const STAFF_CACHE_MS = 10 * 60_000;
/** The console report reuses a rollup written this recently. */
const REPORT_FRESH_MS = 30_000;

export type StaffRow = {
  tenantId: string;
  slug: string;
  name: string;
  kind: string;
  developers: number;
  avgPromptsPerDeveloperPerDay: number;
  overBudget: boolean;
} & FrictionNumbers;
const DAY = 86_400_000;
const SCAN_EVERY_MS = 6 * 3_600_000;

/** The staff list, and the workspaces that could not be read (so a gap is never silent). */
export interface StaffReport {
  workspaces: StaffRow[];
  failed: string[];
}

interface RolledRow {
  day: Date;
  subject: string;
  prompts: number;
  approvals: number;
  denies: number;
  expired: number;
  denied_later_approved: number;
  answered: number;
  answer_ms: number;
  blocked_ms: number;
}

@Injectable()
export class FrictionService {
  private readonly logger = new Logger(FrictionService.name);
  private lastScan = 0;
  /** The staff rollup walks every workspace: keep it for a few minutes per window. */
  private readonly staffCache = new Map<
    number,
    { at: number; value: StaffReport }
  >();

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
  ) {}

  /**
   * Rolls up `host_approvals` into `friction_daily`. Today and yesterday are always recomputed
   * (answers and the 24-hour "denied then approved" window land late); older days only when
   * missing. Idempotent: it replaces a day's rows. No scheduler: it runs when someone reads.
   * ponytail: one grouped query over the window; add a nightly job if workspaces get big.
   */
  async refresh(
    client: TenantPrismaClient,
    days: number,
    now: Date = new Date(),
    /** Skip the work when the rollup was written this recently (the console GET passes one). */
    freshForMs = 0,
  ): Promise<void> {
    const range = dayRange(now, days);
    if (freshForMs > 0) {
      const last = await client.frictionDaily.aggregate({
        where: { day: { gte: range[0]! } },
        _max: { updatedAt: true },
      });
      const at = last._max.updatedAt?.getTime();
      if (at !== undefined && Date.now() - at < freshForMs) return;
    }
    const have = new Set(
      (
        await client.frictionDaily.findMany({
          where: { day: { gte: range[0]! } },
          select: { day: true },
          distinct: ['day'],
        })
      ).map((r) => dayKey(r.day)),
    );
    const recent = new Set(range.slice(-2).map(dayKey));
    const need = range.filter(
      (d) => recent.has(dayKey(d)) || !have.has(dayKey(d)),
    );
    if (need.length === 0) return;
    const from = need[0]!;
    const to = new Date(range[range.length - 1]!.getTime() + DAY);
    const rows = await client.$queryRaw<RolledRow[]>`
      SELECT a."createdAt"::date AS day,
             COALESCE(h."ownerSubject", ${UNASSIGNED}) AS subject,
             COUNT(*)::int AS prompts,
             (COUNT(*) FILTER (WHERE a.status IN ('APPROVED', 'REVOKED')))::int AS approvals,
             (COUNT(*) FILTER (WHERE a.status = 'DENIED'))::int AS denies,
             (COUNT(*) FILTER (WHERE a.status = 'EXPIRED'))::int AS expired,
             (COUNT(*) FILTER (WHERE a.status = 'DENIED' AND EXISTS (
                SELECT 1 FROM host_approvals b
                WHERE b."hostId" = a."hostId" AND b."toolId" = a."toolId"
                  AND b."actionId" = a."actionId" AND b.resource = a.resource
                  AND b.status IN ('APPROVED', 'REVOKED')
                  AND b."createdAt" > a."decidedAt"
                  AND b."createdAt" <= a."decidedAt" + interval '24 hours')))::int
               AS denied_later_approved,
             (COUNT(*) FILTER (WHERE a."decidedAt" IS NOT NULL))::int AS answered,
             COALESCE(SUM(EXTRACT(EPOCH FROM (a."decidedAt" - a."createdAt")) * 1000)
               FILTER (WHERE a."decidedAt" IS NOT NULL), 0)::float8 AS answer_ms,
             COALESCE(SUM(EXTRACT(EPOCH FROM (CASE
                 WHEN a."decidedAt" IS NOT NULL THEN a."decidedAt" - a."createdAt"
                 WHEN a.status = 'EXPIRED'
                   THEN LEAST(a."expiresAt" - a."createdAt", interval '2 minutes')
                 ELSE interval '0' END)) * 1000), 0)::float8 AS blocked_ms
      FROM host_approvals a
      JOIN hosts h ON h.id = a."hostId"
      WHERE a."createdAt" >= ${from} AND a."createdAt" < ${to}
      GROUP BY 1, 2`;
    const needKeys = new Set(need.map(dayKey));
    const fresh = rows.filter((r) => needKeys.has(dayKey(r.day)));
    // One writer at a time per workspace database: two readers refreshing the same day would
    // otherwise both insert it (unique key) and one request would fail with a 500.
    await client.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext('friction_daily'))`;
      await tx.frictionDaily.deleteMany({ where: { day: { in: need } } });
      await tx.frictionDaily.createMany({
        data: fresh.map((r) => ({
          day: r.day,
          subject: r.subject,
          prompts: r.prompts,
          approvals: r.approvals,
          denies: r.denies,
          expired: r.expired,
          deniedLaterApproved: r.denied_later_approved,
          answered: r.answered,
          answerMs: Math.round(r.answer_ms),
          blockedMs: Math.round(r.blocked_ms),
        })),
      });
    });
  }

  private async developers(client: TenantPrismaClient): Promise<number> {
    const owners = await client.host.findMany({
      where: {
        status: 'APPROVED',
        removedAt: null,
        ownerSubject: { not: null },
      },
      select: { ownerSubject: true },
      distinct: ['ownerSubject'],
    });
    return owners.length;
  }

  /**
   * The console report. An approver sees the workspace and every person; anyone else sees only
   * themselves. The 5-prompts-per-developer budget is workspace-wide, so it is only reported
   * to approvers; a person sees their own average against the same line.
   */
  async report(
    client: TenantPrismaClient,
    viewer: { subject: string; admin: boolean },
    days: number,
    now: Date = new Date(),
  ) {
    await this.refresh(client, days, now, REPORT_FRESH_MS);
    const range = dayRange(now, days);
    const all = (await client.frictionDaily.findMany({
      where: { day: { gte: range[0]! } },
    })) as FrictionRow[];
    const rows = viewer.admin
      ? all
      : all.filter((r) => r.subject === viewer.subject);
    const developers = viewer.admin ? await this.developers(client) : 1;
    const perDay = range.map((d) => {
      const k = dayKey(d);
      return { day: k, ...numbers(rows.filter((r) => dayKey(r.day) === k)) };
    });
    const totals = numbers(rows);
    const avg = promptsPerDeveloperPerDay(totals.prompts, developers, days);
    let people:
      Array<FrictionNumbers & { name: string | null; me: boolean }> | undefined;
    if (viewer.admin) {
      const subjects = [...new Set(rows.map((r) => r.subject))];
      const profiles = await client.userProfile.findMany({
        where: { keycloakSubject: { in: subjects } },
        select: { keycloakSubject: true, displayName: true },
      });
      const name = new Map(
        profiles.map((p) => [p.keycloakSubject, p.displayName]),
      );
      people = subjects
        .map((s) => ({
          name: s === UNASSIGNED ? null : (name.get(s) ?? null),
          me: s === viewer.subject,
          ...numbers(rows.filter((r) => r.subject === s)),
        }))
        .sort((a, b) => b.prompts - a.prompts);
    }
    return {
      scope: viewer.admin ? ('workspace' as const) : ('me' as const),
      days,
      budget: FRICTION_BUDGET,
      developers,
      avgPromptsPerDeveloperPerDay: avg,
      overBudget: overBudget(avg),
      totals,
      series: perDay,
      ...(people ? { people } : {}),
    };
  }

  /**
   * Staff: the same numbers per workspace, flagged above the budget. Cached for 10 minutes per
   * window, so Desk polling and the alert scan do not walk every workspace each time.
   */
  async staff(days: number, now: Date = new Date()): Promise<StaffRow[]> {
    return (await this.staffReport(days, now)).workspaces;
  }

  async staffReport(
    days: number,
    now: Date = new Date(),
  ): Promise<StaffReport> {
    const hit = this.staffCache.get(days);
    if (hit && now.getTime() - hit.at < STAFF_CACHE_MS) return hit.value;
    const value = await this.computeStaff(days, now);
    this.staffCache.set(days, { at: now.getTime(), value });
    return value;
  }

  private async computeStaff(days: number, now: Date): Promise<StaffReport> {
    const tenants = await this.control.tenant.findMany({
      where: { status: 'ACTIVE', kind: { not: 'SAMPLE' } },
      select: { id: true, slug: true, name: true, kind: true },
      orderBy: { createdAt: 'asc' },
      take: 1000,
    });
    const out: StaffRow[] = [];
    const failed: string[] = [];
    // ponytail: one workspace at a time; the tenant client cache holds 50, so a very large
    // fleet should read a nightly platform rollup instead.
    for (const t of tenants) {
      try {
        const client = await this.tenants.getClient(t.id);
        await this.refresh(client, days, now);
        const range = dayRange(now, days);
        const rows = (await client.frictionDaily.findMany({
          where: { day: { gte: range[0]! } },
        })) as FrictionRow[];
        const totals = numbers(rows);
        const developers = await this.developers(client);
        const avg = promptsPerDeveloperPerDay(totals.prompts, developers, days);
        out.push({
          tenantId: t.id,
          slug: t.slug,
          name: t.name,
          kind: t.kind,
          developers,
          avgPromptsPerDeveloperPerDay: avg,
          overBudget: overBudget(avg),
          ...totals,
        });
      } catch (error) {
        failed.push(t.slug);
        this.logger.warn(
          `friction rollup failed for ${t.slug}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
    if (failed.length > 0)
      this.logger.warn(
        `friction rollup skipped ${failed.length} workspace(s): ${failed.slice(0, 20).join(', ')}`,
      );
    return {
      workspaces: out.sort(
        (a, b) =>
          b.avgPromptsPerDeveloperPerDay - a.avgPromptsPerDeveloperPerDay,
      ),
      failed,
    };
  }

  /**
   * Alert path (decision 38): one warn line per workspace over budget and a gauge with the count
   * (no tenant label; the per-workspace list is the staff API). Once per 6 hours across all
   * replicas (a stamp in the control database), so an hourly tick stays cheap. The gauge is set by
   * the replica that ran the check: read it with max() across replicas.
   */
  async scan(now: Date = new Date()): Promise<number> {
    // This process asked recently: no database round trip.
    if (now.getTime() - this.lastScan < SCAN_EVERY_MS) return 0;
    this.lastScan = now.getTime();
    // One replica per interval wins the stamp; the others return at once.
    if (!(await this.claimScan(now))) return 0;
    const over = (await this.staff(7, now)).filter((w) => w.overBudget);
    for (const w of over)
      this.logger.warn(
        `friction over budget: ${w.slug} averages ${w.avgPromptsPerDeveloperPerDay} prompts per developer per day (budget ${FRICTION_BUDGET}) over 7 days`,
      );
    setFrictionOverBudget(over.length);
    return over.length;
  }

  /** Conditional upsert: true only for the caller that moved `ranAt` (or created the row). */
  private async claimScan(now: Date): Promise<boolean> {
    const due = new Date(now.getTime() - SCAN_EVERY_MS);
    const n = await this.control.$executeRaw`
      INSERT INTO job_runs (name, "ranAt") VALUES ('friction-scan', ${now})
      ON CONFLICT (name) DO UPDATE SET "ranAt" = ${now}
      WHERE job_runs."ranAt" <= ${due}`;
    return n > 0;
  }
}
