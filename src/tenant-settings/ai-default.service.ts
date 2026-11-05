import { Injectable, Logger } from '@nestjs/common';
import { Prisma } from '../generated/tenant-client/client';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';

export interface AiDefaultCounts {
  /** Would be (dry run) or were switched on. */
  flip: number;
  /** Still at false with an owner's own choice on record: left alone. */
  keptExplicit: number;
  skippedGovernment: number;
  /** Customer-hosted deployments are never flipped. */
  skippedCustomerDeployment: number;
  /** Sector not known (or not confirmed commercial): left alone, needs a person to decide. */
  needsReview: number;
  skippedAirGapped: number;
  /** Not ACTIVE yet (queued, provisioning, suspended...): no audit log to read; run again later. */
  skippedNotActive: number;
  /** ACTIVE but the workspace's audit log could not be read: left alone, run again. */
  failed: number;
}

/**
 * The founder's default (5 Nov 2026): AI on for Free, Pro and Company workspaces, off for
 * Government and air-gapped ones. Existing workspaces are still at the old `false` default or hold
 * an owner's own choice, and only each workspace's audit log tells them apart, so this reads it.
 * Only workspaces whose sector is recorded as COMMERCIAL, on a hosted deployment, are flipped.
 * Idempotent; the dry run reads only (read-only transactions) and returns counts, never identifiers.
 */
@Injectable()
export class AiDefaultService {
  private readonly logger = new Logger(AiDefaultService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly audit: AuditService,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  async run(options: { dryRun: boolean }): Promise<AiDefaultCounts> {
    const counts: AiDefaultCounts = {
      flip: 0,
      keptExplicit: 0,
      skippedGovernment: 0,
      skippedCustomerDeployment: 0,
      needsReview: 0,
      skippedAirGapped: 0,
      skippedNotActive: 0,
      failed: 0,
    };
    const rows = await this.control.$transaction(async (tx) => {
      await tx.$executeRaw`SET TRANSACTION READ ONLY`;
      const government = new Set(
        (
          await tx.enterpriseProfile.findMany({
            where: { sector: 'GOVERNMENT' },
            select: { tenantId: true },
          })
        ).map((p) => p.tenantId),
      );
      const found = await tx.tenant.findMany({
        where: { allowExternalAi: false, status: { not: 'DELETED' } },
        select: {
          id: true,
          status: true,
          residency: true,
          sector: true,
          allowExternalAiChosen: true,
        },
        orderBy: { createdAt: 'asc' },
      });
      return found.map((t) => ({
        ...t,
        government: t.sector === 'GOVERNMENT' || government.has(t.id),
      }));
    });

    for (const t of rows) {
      if (t.residency === 'AIR_GAPPED') counts.skippedAirGapped++;
      else if (t.government) counts.skippedGovernment++;
      else if (t.allowExternalAiChosen) counts.keptExplicit++;
      else if (
        this.config.get('MANAR_DEPLOYMENT', { infer: true }) !== 'hosted'
      )
        counts.skippedCustomerDeployment++;
      // Only a positively known commercial sector is flipped; unknown waits for a person.
      else if (t.sector !== 'COMMERCIAL') counts.needsReview++;
      else if (t.status !== 'ACTIVE') counts.skippedNotActive++;
      else await this.one(t.id, options.dryRun, counts);
    }
    return counts;
  }

  private async one(
    tenantId: string,
    dryRun: boolean,
    counts: AiDefaultCounts,
  ): Promise<void> {
    try {
      const client = await this.tenants.getClient(tenantId);
      const explicit = await client.$transaction(async (tx) => {
        await tx.$executeRaw`SET TRANSACTION READ ONLY`;
        const hit = await tx.auditEvent.findFirst({
          where: {
            eventType: AUDIT_EVENT_TYPES.TENANT_SETTINGS_UPDATED,
            // An update that touched allowExternalAi carries the key in its data.
            data: { path: ['allowExternalAi'], not: Prisma.JsonNull },
          },
          select: { id: true },
        });
        return hit !== null;
      });
      if (explicit) {
        counts.keptExplicit++;
        if (!dryRun) {
          await this.control.tenant.updateMany({
            where: { id: tenantId, allowExternalAiChosen: false },
            data: { allowExternalAiChosen: true },
          });
        }
        return;
      }
      if (dryRun) {
        counts.flip++;
        return;
      }
      // Guarded write: a concurrent owner choice or an earlier run makes this a no-op.
      const { count } = await this.control.tenant.updateMany({
        where: {
          id: tenantId,
          allowExternalAi: false,
          allowExternalAiChosen: false,
        },
        data: { allowExternalAi: true, aiDefaultNoticePending: true },
      });
      if (count === 0) return;
      counts.flip++;
      await this.audit.recordSafely(client, tenantId, {
        eventType: AUDIT_EVENT_TYPES.TENANT_AI_DEFAULT_APPLIED,
        actor: { type: 'system', id: 'ai:default-on' },
        data: { allowExternalAi: true, from: false },
      });
    } catch (error) {
      counts.failed++;
      this.logger.error(
        `ai:default-on could not process one workspace: ${error instanceof Error ? error.constructor.name : 'error'}`,
      );
    }
  }
}
