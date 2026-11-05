import { Injectable, Logger } from '@nestjs/common';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { AuditService } from './audit.service';

export type FullCheckState = 'passed' | 'failed' | 'never';

export interface FullVerifyStatus {
  state: FullCheckState;
  /** Set only when the last full check passed. */
  lastFullVerifiedAt: Date | null;
  brokenAt: string | null;
}

/**
 * Nightly FULL audit verification (the dashboard polls the cheap incremental mode). The result
 * lives in the control database, outside the tenant database an attacker would be rewriting.
 */
@Injectable()
export class AuditFullVerifyService {
  /** A second worker replica skips tenants checked within this window. */
  static readonly MIN_INTERVAL_MS = 20 * 3_600_000;

  private readonly logger = new Logger(AuditFullVerifyService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly audit: AuditService,
  ) {}

  async status(tenantId: string): Promise<FullVerifyStatus> {
    const row = await this.control.auditFullVerification.findUnique({
      where: { tenantId },
    });
    if (!row)
      return { state: 'never', lastFullVerifiedAt: null, brokenAt: null };
    return row.valid
      ? { state: 'passed', lastFullVerifiedAt: row.verifiedAt, brokenAt: null }
      : { state: 'failed', lastFullVerifiedAt: null, brokenAt: row.brokenAt };
  }

  /** Full walk of one tenant, result stored. A thrown error stores nothing (stays failed/never). */
  async verifyTenant(tenantId: string): Promise<boolean> {
    const client = await this.tenants.getClient(tenantId);
    const result = await this.audit.verifyAuditChain(client, tenantId);
    const data = {
      verifiedAt: new Date(),
      valid: result.valid,
      brokenAt: result.valid ? null : result.brokenAt,
    };
    await this.control.auditFullVerification.upsert({
      where: { tenantId },
      create: { tenantId, ...data },
      update: data,
    });
    if (!result.valid) {
      this.logger.error(
        `Full audit verification FAILED for tenant "${tenantId}" at ${result.brokenAt}`,
      );
    }
    return result.valid;
  }

  /** Every ACTIVE tenant, one at a time (a full walk is heavy); one failure never stops the rest. */
  async runAll(now = Date.now()): Promise<{ checked: number; failed: number }> {
    const tenants = await this.control.tenant.findMany({
      where: { status: 'ACTIVE' },
      select: { id: true },
    });
    let checked = 0;
    let failed = 0;
    for (const { id } of tenants) {
      try {
        const prev = await this.control.auditFullVerification.findUnique({
          where: { tenantId: id },
        });
        if (
          prev &&
          now - prev.verifiedAt.getTime() <
            AuditFullVerifyService.MIN_INTERVAL_MS
        ) {
          continue;
        }
        checked++;
        if (!(await this.verifyTenant(id))) failed++;
      } catch (error) {
        this.logger.error(
          `Full audit verification errored for tenant "${id}": ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
    return { checked, failed };
  }
}

/** Body of `GET /audit/verify`: a failed last full check is never reported as valid. */
export function composeVerifyResponse(
  incremental: { valid: true } | { valid: false; brokenAt: string },
  full: FullVerifyStatus,
): {
  valid: boolean;
  brokenAt?: string;
  lastFullVerifiedAt: string | null;
  fullCheck: FullCheckState;
} {
  const base = {
    lastFullVerifiedAt: full.lastFullVerifiedAt?.toISOString() ?? null,
    fullCheck: full.state,
  };
  if (!incremental.valid)
    return { ...base, valid: false, brokenAt: incremental.brokenAt };
  if (full.state === 'failed') {
    return { ...base, valid: false, brokenAt: full.brokenAt ?? 'full_check' };
  }
  return { ...base, valid: true };
}
