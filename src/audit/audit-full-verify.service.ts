import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { registerAuditVerifyMetrics } from '../metrics/metrics';
import { AuditService, type VerifyAuditChainResult } from './audit.service';

/**
 * `passed`: the last full check passed and is recent. `stale`: it passed but is older than
 * STALE_MS (the nightly job stopped). `failed`: the last full check found a break. `error`: the
 * last run threw (unreadable row, database down): never "verified". `never`: no full check yet.
 */
export type FullCheckState = 'passed' | 'stale' | 'failed' | 'error' | 'never';

export interface FullVerifyStatus {
  state: FullCheckState;
  /** Start of the newest full check that passed (may be old: read `state`). */
  lastFullVerifiedAt: Date | null;
  brokenAt: string | null;
}

const HOUR = 3_600_000;

/** Most recent 22:00 UTC (02:00 in the UAE) at or before `now`: the nightly run is due after it. */
export function lastNightlyBoundary(now: Date): Date {
  const d = new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 22),
  );
  return d.getTime() <= now.getTime() ? d : new Date(d.getTime() - 24 * HOUR);
}

type Row = {
  verifiedAt: Date | null;
  result: string | null;
  brokenAt: string | null;
  lastPassedAt: Date | null;
  durationMs: number | null;
} | null;

/**
 * FULL audit verification (the console polls the cheap incremental mode). Results live in the
 * control database, outside the tenant database an attacker would be rewriting.
 */
@Injectable()
export class AuditFullVerifyService implements OnModuleInit, OnModuleDestroy {
  /** A pass older than this is `stale`: the nightly job should have run again (24 h + slack). */
  static readonly STALE_MS = 26 * HOUR;
  /** A claim older than this is a crashed worker, not a run in progress. */
  static readonly CLAIM_TTL_MS = 2 * HOUR;
  /** An errored tenant is retried after this long (not every tick). */
  static readonly ERROR_RETRY_MS = 6 * HOUR;

  private readonly logger = new Logger(AuditFullVerifyService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly audit: AuditService,
  ) {}

  onModuleInit(): void {
    // Scraped from the API process: the worker's own metrics endpoint is Temporal's exporter.
    registerAuditVerifyMetrics(() => this.metricsSnapshot());
  }

  onModuleDestroy(): void {
    registerAuditVerifyMetrics(null);
  }

  /** No tenant label: newest pass over all tenants, and the newest run's duration. */
  async metricsSnapshot(): Promise<{
    lastSuccessSeconds: number | null;
    lastDurationSeconds: number | null;
  }> {
    const [pass, run] = await Promise.all([
      this.control.auditFullVerification.aggregate({
        _max: { lastPassedAt: true },
      }),
      this.control.auditFullVerification.findFirst({
        where: { durationMs: { not: null } },
        orderBy: { verifiedAt: 'desc' },
        select: { durationMs: true },
      }),
    ]);
    return {
      lastSuccessSeconds: pass._max.lastPassedAt
        ? Math.floor(pass._max.lastPassedAt.getTime() / 1000)
        : null,
      lastDurationSeconds:
        run?.durationMs != null ? run.durationMs / 1000 : null,
    };
  }

  async status(tenantId: string, now = Date.now()): Promise<FullVerifyStatus> {
    const row = await this.control.auditFullVerification.findUnique({
      where: { tenantId },
    });
    return statusOf(row, now);
  }

  /**
   * Full walk of one tenant, result recorded. A run that throws records `error` (so an old
   * `passed` can never outlive a night the check could not complete) and rethrows. Used by the
   * nightly job, the platform verify and the `audit:verify` CLI.
   */
  async verifyTenant(tenantId: string): Promise<VerifyAuditChainResult> {
    const startedAt = new Date();
    try {
      const client = await this.tenants.getClient(tenantId);
      const result = await this.audit.verifyAuditChain(client, tenantId);
      await this.record(
        tenantId,
        startedAt,
        result.valid ? 'passed' : 'failed',
        {
          brokenAt: result.valid ? null : result.brokenAt,
        },
      );
      if (!result.valid) {
        this.logger.error(
          `Full audit verification FAILED for tenant "${tenantId}" at ${result.brokenAt}`,
        );
      }
      return result;
    } catch (error) {
      await this.record(tenantId, startedAt, 'error', { brokenAt: null }).catch(
        () => undefined,
      );
      throw error;
    }
  }

  /**
   * Every ACTIVE tenant that is due, one at a time (a full walk is heavy). A tenant is due when
   * its newest run started before the last 22:00 UTC boundary (so a worker restarted after 22:00
   * still runs tonight), or it errored more than ERROR_RETRY_MS ago. Each tenant is claimed with
   * a conditional write first: a second worker replica skips it.
   */
  async runAll(now = new Date()): Promise<{
    checked: number;
    failed: number;
    errored: number;
  }> {
    const tenants = await this.control.tenant.findMany({
      where: { status: 'ACTIVE' },
      select: { id: true },
    });
    const dueBefore = lastNightlyBoundary(now);
    let checked = 0;
    let failed = 0;
    let errored = 0;
    for (const { id } of tenants) {
      if (!(await this.claim(id, now, dueBefore))) continue;
      checked++;
      try {
        if (!(await this.verifyTenant(id)).valid) failed++;
      } catch (error) {
        errored++;
        this.logger.error(
          `Full audit verification errored for tenant "${id}": ${error instanceof Error ? error.message : String(error)}`,
        );
      } finally {
        await this.release(id).catch(() => undefined);
      }
    }
    return { checked, failed, errored };
  }

  /** True when this caller now owns the tenant's run. */
  async claim(tenantId: string, now: Date, dueBefore: Date): Promise<boolean> {
    const staleClaim = new Date(
      now.getTime() - AuditFullVerifyService.CLAIM_TTL_MS,
    );
    const retryBefore = new Date(
      now.getTime() - AuditFullVerifyService.ERROR_RETRY_MS,
    );
    const rows = await this.control.$queryRaw<unknown[]>`
      INSERT INTO "audit_full_verifications" ("tenantId", "claimedAt", "updatedAt")
      VALUES (${tenantId}, ${now}, ${now})
      ON CONFLICT ("tenantId") DO UPDATE
        SET "claimedAt" = ${now}, "updatedAt" = ${now}
        WHERE ("audit_full_verifications"."claimedAt" IS NULL
               OR "audit_full_verifications"."claimedAt" < ${staleClaim})
          AND ("audit_full_verifications"."verifiedAt" IS NULL
               OR "audit_full_verifications"."verifiedAt" < ${dueBefore}
               OR ("audit_full_verifications"."result" = 'error'
                   AND "audit_full_verifications"."verifiedAt" < ${retryBefore}))
      RETURNING 1`;
    return rows.length > 0;
  }

  private async release(tenantId: string): Promise<void> {
    await this.control.$executeRaw`
      UPDATE "audit_full_verifications" SET "claimedAt" = NULL WHERE "tenantId" = ${tenantId}`;
  }

  /** Stores a run's result unless a run that started later already did (never older over newer). */
  private async record(
    tenantId: string,
    startedAt: Date,
    result: 'passed' | 'failed' | 'error',
    extra: { brokenAt: string | null },
  ): Promise<void> {
    const durationMs = Date.now() - startedAt.getTime();
    const passedAt = result === 'passed' ? startedAt : null;
    await this.control.$executeRaw`
      INSERT INTO "audit_full_verifications" AS t
        ("tenantId", "verifiedAt", "result", "brokenAt", "lastPassedAt", "durationMs", "updatedAt")
      VALUES (${tenantId}, ${startedAt}, ${result}, ${extra.brokenAt}, ${passedAt}, ${durationMs}, now())
      ON CONFLICT ("tenantId") DO UPDATE SET
        "verifiedAt" = CASE WHEN t."verifiedAt" IS NULL OR t."verifiedAt" <= EXCLUDED."verifiedAt"
                            THEN EXCLUDED."verifiedAt" ELSE t."verifiedAt" END,
        "result" = CASE WHEN t."verifiedAt" IS NULL OR t."verifiedAt" <= EXCLUDED."verifiedAt"
                        THEN EXCLUDED."result" ELSE t."result" END,
        "brokenAt" = CASE WHEN t."verifiedAt" IS NULL OR t."verifiedAt" <= EXCLUDED."verifiedAt"
                          THEN EXCLUDED."brokenAt" ELSE t."brokenAt" END,
        "durationMs" = CASE WHEN t."verifiedAt" IS NULL OR t."verifiedAt" <= EXCLUDED."verifiedAt"
                            THEN EXCLUDED."durationMs" ELSE t."durationMs" END,
        "lastPassedAt" = GREATEST(t."lastPassedAt", EXCLUDED."lastPassedAt"),
        "updatedAt" = now()`;
  }
}

export function statusOf(row: Row, now: number): FullVerifyStatus {
  const lastFullVerifiedAt = row?.lastPassedAt ?? null;
  if (!row || !row.result) {
    return { state: 'never', lastFullVerifiedAt, brokenAt: null };
  }
  if (row.result === 'failed') {
    return { state: 'failed', lastFullVerifiedAt, brokenAt: row.brokenAt };
  }
  if (row.result === 'error') {
    return { state: 'error', lastFullVerifiedAt, brokenAt: null };
  }
  const fresh =
    lastFullVerifiedAt !== null &&
    now - lastFullVerifiedAt.getTime() <= AuditFullVerifyService.STALE_MS;
  return {
    state: fresh ? 'passed' : 'stale',
    lastFullVerifiedAt,
    brokenAt: null,
  };
}

export type VerifyResponse = {
  /** True only when everything claimed was checked: see `status`. */
  valid: boolean;
  /** verified: whole log covered; partial: incremental passed but no fresh full pass; broken. */
  status: 'verified' | 'partial' | 'broken';
  brokenAt?: string;
  lastFullVerifiedAt: string | null;
  fullCheck: FullCheckState;
  /** Set when the incremental check skipped older events: the SEAL it resumed from. */
  coveredFrom?: { sealSeq: string; at: string };
};

/**
 * Body of `GET /audit/verify`. `valid: true` only if the incremental check passed AND either it
 * walked the whole log or the last full check passed recently. A failed last full check is broken.
 */
export function composeVerifyResponse(
  incremental: VerifyAuditChainResult,
  full: FullVerifyStatus,
): VerifyResponse {
  const base = {
    lastFullVerifiedAt: full.lastFullVerifiedAt?.toISOString() ?? null,
    fullCheck: full.state,
  };
  if (!incremental.valid) {
    return {
      ...base,
      valid: false,
      status: 'broken',
      brokenAt: incremental.brokenAt,
    };
  }
  if (full.state === 'failed') {
    return {
      ...base,
      valid: false,
      status: 'broken',
      brokenAt: full.brokenAt ?? 'full_check',
    };
  }
  if (!incremental.coveredFrom || full.state === 'passed') {
    return { ...base, valid: true, status: 'verified' };
  }
  return {
    ...base,
    valid: false,
    status: 'partial',
    coveredFrom: {
      sealSeq: incremental.coveredFrom.sealSeq,
      at: incremental.coveredFrom.at.toISOString(),
    },
  };
}
