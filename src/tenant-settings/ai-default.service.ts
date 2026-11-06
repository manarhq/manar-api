import { randomUUID } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import { Prisma } from '../generated/tenant-client/client';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';

export interface AiDefaultCounts {
  /** Would be (dry run) or were switched on. `flipPersonal + flipEnterprise`. */
  flip: number;
  /** Of `flip`: personal workspaces. */
  flipPersonal: number;
  /** Of `flip`: company (enterprise) workspaces. A live run flips these only with `--include-enterprise`. */
  flipEnterprise: number;
  /** Live run without `--include-enterprise`: company workspaces that would flip and were left for staff to confirm. */
  enterpriseHeld: number;
  /** The guarded flip matched nothing: sector, residency, status or the owner's choice changed after it was read. */
  changedMidRun: number;
  /** Flipped, but the completion event could not be written; the next run reconciles it. */
  completionFailed: number;
  /** A flip whose completion event was missing and has now been written from the row's real state. */
  reconciled: number;
  /** Still at false with an owner's own choice on record: left alone. */
  keptExplicit: number;
  skippedGovernment: number;
  /** Customer-hosted deployments are never flipped. */
  skippedCustomerDeployment: number;
  /** Sector not known (or not confirmed commercial): left off; the owner is shown the opt-in notice. */
  needsReview: number;
  skippedAirGapped: number;
  /** Not ACTIVE yet (queued, provisioning, suspended...): no audit log to read; run again later. */
  skippedNotActive: number;
  /** The audit history cannot prove no choice was made (pruned, anchored, or not reaching back to creation): AI stays off and the owner is asked. */
  historyIncomplete: number;
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
/** ponytail: a first event up to a week after creation still counts as "reaches back"; an idle new workspace is the case this tolerates. */
const FIRST_EVENT_TOLERANCE_MS = 7 * 24 * 3_600_000;

export function historyCoversLife(
  log: { oldest: Date | undefined; anchors: number },
  createdAt: Date,
): boolean {
  if (log.anchors > 0) return false;
  // No event at all: nothing was pruned and no choice was ever recorded.
  if (!log.oldest) return true;
  return log.oldest.getTime() <= createdAt.getTime() + FIRST_EVENT_TOLERANCE_MS;
}

@Injectable()
export class AiDefaultService {
  private readonly logger = new Logger(AiDefaultService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly audit: AuditService,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  async run(options: {
    dryRun: boolean;
    includeEnterprise?: boolean;
  }): Promise<AiDefaultCounts> {
    const counts: AiDefaultCounts = {
      flip: 0,
      flipPersonal: 0,
      flipEnterprise: 0,
      enterpriseHeld: 0,
      changedMidRun: 0,
      completionFailed: 0,
      reconciled: 0,
      keptExplicit: 0,
      skippedGovernment: 0,
      skippedCustomerDeployment: 0,
      needsReview: 0,
      historyIncomplete: 0,
      skippedAirGapped: 0,
      skippedNotActive: 0,
      failed: 0,
    };
    const hosted =
      this.config.get('MANAR_DEPLOYMENT', { infer: true }) === 'hosted';
    const { rows, onByDefault } = await this.control.$transaction(
      async (tx) => {
        await tx.$executeRaw`SET TRANSACTION READ ONLY`;
        const government = new Set(
          (
            await tx.enterpriseProfile.findMany({
              where: { sector: 'GOVERNMENT' },
              select: { tenantId: true },
            })
          ).map((p) => p.tenantId),
        );
        const select = {
          id: true,
          status: true,
          residency: true,
          sector: true,
          kind: true,
          createdAt: true,
          allowExternalAiChosen: true,
        } as const;
        const found = await tx.tenant.findMany({
          where: { allowExternalAi: false, status: { not: 'DELETED' } },
          select,
          orderBy: { createdAt: 'asc' },
        });
        // Switched on and not an owner's choice: a flip by an earlier run may lack its completion.
        const on = hosted
          ? await tx.tenant.findMany({
              where: {
                allowExternalAi: true,
                allowExternalAiChosen: false,
                status: 'ACTIVE',
              },
              select: { id: true },
            })
          : [];
        return {
          rows: found.map((t) => ({
            ...t,
            government: t.sector === 'GOVERNMENT' || government.has(t.id),
          })),
          onByDefault: on.map((t) => t.id),
        };
      },
    );

    for (const t of rows) {
      if (t.residency === 'AIR_GAPPED') counts.skippedAirGapped++;
      else if (t.government) counts.skippedGovernment++;
      else if (t.allowExternalAiChosen) counts.keptExplicit++;
      else if (!hosted) counts.skippedCustomerDeployment++;
      // Only a positively known commercial sector is flipped; unknown stays off and the owner is asked.
      else if (t.sector !== 'COMMERCIAL') {
        counts.needsReview++;
        if (!options.dryRun && t.status === 'ACTIVE') await this.askOwner(t.id);
      } else if (t.status !== 'ACTIVE') counts.skippedNotActive++;
      else await this.one(t, options, counts);
    }
    for (const id of onByDefault) await this.reconcile(id, options, counts);
    return counts;
  }

  /** needsReview: AI stays off and the owner sees the "Turn on AI features?" notice. */
  private async askOwner(tenantId: string): Promise<void> {
    await this.control.tenant.updateMany({
      where: {
        id: tenantId,
        allowExternalAi: false,
        allowExternalAiChosen: false,
        aiOptInNoticePending: false,
      },
      data: { aiOptInNoticePending: true },
    });
  }

  /**
   * One guarded UPDATE: the flip happens only if, at this instant, the workspace is still a
   * commercial, non-air-gapped, ACTIVE, non-Government one with no choice of its own. Returns the
   * number of rows changed (0 or 1).
   */
  async guardedFlip(tenantId: string): Promise<number> {
    return this.control.$executeRaw`
      UPDATE "tenants" t
         SET "allowExternalAi" = true, "aiDefaultNoticePending" = true, "updatedAt" = now()
       WHERE t."id" = ${tenantId}
         AND t."allowExternalAi" = false
         AND t."allowExternalAiChosen" = false
         AND t."sector" = 'COMMERCIAL'
         AND t."residency" <> 'AIR_GAPPED'
         AND t."status" = 'ACTIVE'
         AND NOT EXISTS (
           SELECT 1 FROM "enterprise_profiles" p
            WHERE p."tenantId" = t."id" AND p."sector" = 'GOVERNMENT')`;
  }

  private async one(
    t: { id: string; createdAt: Date; kind: string },
    options: { dryRun: boolean; includeEnterprise?: boolean },
    counts: AiDefaultCounts,
  ): Promise<void> {
    const tenantId = t.id;
    const dryRun = options.dryRun;
    try {
      const client = await this.tenants.getClient(tenantId);
      const log = await client.$transaction(async (tx) => {
        await tx.$executeRaw`SET TRANSACTION READ ONLY`;
        const hit = await tx.auditEvent.findFirst({
          where: {
            eventType: AUDIT_EVENT_TYPES.TENANT_SETTINGS_UPDATED,
            // An update that touched allowExternalAi carries the key in its data.
            data: { path: ['allowExternalAi'], not: Prisma.JsonNull },
          },
          select: { id: true },
        });
        const oldest = await tx.auditEvent.findFirst({
          orderBy: { timestamp: 'asc' },
          select: { timestamp: true },
        });
        const anchors = await tx.auditChainAnchor.count();
        return { explicit: hit !== null, oldest: oldest?.timestamp, anchors };
      });
      if (log.explicit) {
        counts.keptExplicit++;
        if (!dryRun) {
          await this.control.tenant.updateMany({
            where: { id: tenantId, allowExternalAiChosen: false },
            data: { allowExternalAiChosen: true },
          });
        }
        return;
      }
      // A missing settings event proves nothing unless the history covers the workspace's whole
      // life: a retention prune leaves an anchor, and the oldest surviving event must reach back to
      // creation. Write failures leave no record before this release (see PR), so they cannot be
      // excluded here; the settings change now fails if its audit write does.
      if (!historyCoversLife(log, t.createdAt)) {
        counts.historyIncomplete++;
        if (!dryRun) {
          await this.control.tenant.updateMany({
            where: { id: tenantId, aiOptInNoticePending: false },
            data: { aiOptInNoticePending: true },
          });
        }
        return;
      }
      const enterprise = t.kind !== 'PERSONAL';
      if (enterprise) counts.flipEnterprise++;
      else counts.flipPersonal++;
      if (dryRun) {
        counts.flip++;
        return;
      }
      if (enterprise && !options.includeEnterprise) {
        counts.flipEnterprise--;
        counts.enterpriseHeld++;
        return;
      }
      // 1. Intent first. `record` throws: if the intent cannot be written, nothing is changed.
      const intentId = randomUUID();
      const actor = { type: 'system', id: 'ai:default-on' } as const;
      await this.audit.record(client, tenantId, {
        eventType: AUDIT_EVENT_TYPES.TENANT_AI_DEFAULT_INTENT,
        actor,
        data: { intentId, from: false, to: true },
      });
      // 2. The guarded flip.
      const count = await this.guardedFlip(tenantId);
      if (count === 1) counts.flip++;
      else {
        counts.changedMidRun++;
        if (enterprise) counts.flipEnterprise--;
        else counts.flipPersonal--;
      }
      // 3. Completion: what really happened. If this fails the run exits 1 and the next run
      // writes it from the row's state (reconcile).
      try {
        await this.audit.record(client, tenantId, {
          eventType: AUDIT_EVENT_TYPES.TENANT_AI_DEFAULT_APPLIED,
          actor,
          data: {
            intentId,
            applied: count === 1,
            allowExternalAi: count === 1,
          },
        });
      } catch (error) {
        counts.completionFailed++;
        this.logger.error(
          `ai:default-on wrote a change without its completion event for one workspace: ${error instanceof Error ? error.constructor.name : 'error'}`,
        );
      }
    } catch (error) {
      counts.failed++;
      this.logger.error(
        `ai:default-on could not process one workspace: ${error instanceof Error ? error.constructor.name : 'error'}`,
      );
    }
  }

  /**
   * An intent without a completion in a workspace that is now on (and not an owner's choice):
   * the flip happened and its completion write failed. Writes it from the row's actual state.
   * ponytail: reads the last 200 events of each type; a fleet-wide backlog would need paging.
   */
  private async reconcile(
    tenantId: string,
    options: { dryRun: boolean },
    counts: AiDefaultCounts,
  ): Promise<void> {
    try {
      const client = await this.tenants.getClient(tenantId);
      const [intents, done] = await client.$transaction(async (tx) => {
        await tx.$executeRaw`SET TRANSACTION READ ONLY`;
        return [
          await tx.auditEvent.findMany({
            where: { eventType: AUDIT_EVENT_TYPES.TENANT_AI_DEFAULT_INTENT },
            select: { data: true },
            orderBy: { timestamp: 'desc' },
            take: 200,
          }),
          await tx.auditEvent.findMany({
            where: { eventType: AUDIT_EVENT_TYPES.TENANT_AI_DEFAULT_APPLIED },
            select: { data: true },
            orderBy: { timestamp: 'desc' },
            take: 200,
          }),
        ] as const;
      });
      const idOf = (e: { data: unknown }) =>
        (e.data as { intentId?: unknown } | null)?.intentId;
      const completed = new Set(done.map(idOf));
      const missing = intents
        .map(idOf)
        .filter((id): id is string => typeof id === 'string')
        .filter((id) => !completed.has(id));
      for (const intentId of missing) {
        counts.reconciled++;
        if (options.dryRun) continue;
        await this.audit.record(client, tenantId, {
          eventType: AUDIT_EVENT_TYPES.TENANT_AI_DEFAULT_APPLIED,
          actor: { type: 'system', id: 'ai:default-on' },
          data: {
            intentId,
            applied: true,
            allowExternalAi: true,
            reconciled: true,
          },
        });
      }
    } catch (error) {
      counts.failed++;
      this.logger.error(
        `ai:default-on could not reconcile one workspace: ${error instanceof Error ? error.constructor.name : 'error'}`,
      );
    }
  }
}
