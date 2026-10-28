import { Injectable, Optional } from '@nestjs/common';
import { KillSwitchEpochService } from '../kill-switches/kill-switch-epoch.service';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';

/** The tenant-local profile that owns the platform's kill switch (not a person). */
export const PLATFORM_SUBJECT = 'platform:manar-fleet';
export const SUSPEND_REASON = 'tenant_suspended';
/**
 * The platform's own TENANT-scope switch row: fixed id, and `targetId` set to this sentinel so it
 * is never the humans' row (`targetId` null, the one the console toggles). `checkAll` denies on
 * any active TENANT row.
 */
export const PLATFORM_SWITCH_ID = 'platform-suspension';
export const PLATFORM_SWITCH_TARGET = 'platform:manar-fleet';

/**
 * Makes a platform suspend effective on the decision path in every process at once (ADR-0010).
 * The platform writes only its own row, with one conditional statement each way, and the audit
 * event commits in the same transaction (no event, no change). The humans' tenant switch is never
 * read or written here, so a human stop survives any suspend and resume.
 */
@Injectable()
export class PlatformSuspension {
  constructor(
    private readonly audit: AuditService,
    @Optional() private readonly epochs?: KillSwitchEpochService,
  ) {}

  async engage(
    db: TenantPrismaClient,
    tenantId: string,
    caller: string,
  ): Promise<void> {
    const publish = await db.$transaction(async (tx) => {
      const profile = await tx.userProfile.upsert({
        where: { keycloakSubject: PLATFORM_SUBJECT },
        create: {
          keycloakSubject: PLATFORM_SUBJECT,
          email: '',
          displayName: 'Platform (manar-fleet)',
        },
        update: {},
      });
      await tx.$executeRaw`
        INSERT INTO "kill_switches" ("id", "scope", "targetId", "active", "reason", "activatedBy", "activatedAt")
        VALUES (${PLATFORM_SWITCH_ID}, 'TENANT', ${PLATFORM_SWITCH_TARGET}, true, ${SUSPEND_REASON}, ${profile.id}, now())
        ON CONFLICT ("id") DO UPDATE SET
          "active" = true, "reason" = EXCLUDED."reason", "activatedBy" = EXCLUDED."activatedBy",
          "activatedAt" = now(), "deactivatedBy" = NULL, "deactivatedAt" = NULL`;
      return this.audit.recordInTransaction(tx, tenantId, {
        eventType: AUDIT_EVENT_TYPES.KILL_SWITCH_ACTIVATED,
        actor: { type: 'system', id: caller },
        data: {
          killSwitchId: PLATFORM_SWITCH_ID,
          scope: 'TENANT',
          targetId: PLATFORM_SWITCH_TARGET,
          reason: SUSPEND_REASON,
        },
      });
    });
    publish();
    await this.epochs?.bumpTenant(tenantId);
  }

  /** Turns off the platform's own row only. Returns false if it was not active. */
  async release(
    db: TenantPrismaClient,
    tenantId: string,
    caller: string,
  ): Promise<boolean> {
    const result = await db.$transaction(async (tx) => {
      const profile = await tx.userProfile.findUnique({
        where: { keycloakSubject: PLATFORM_SUBJECT },
      });
      const changed = await tx.$executeRaw`
        UPDATE "kill_switches" SET "active" = false, "deactivatedBy" = ${profile?.id ?? null}, "deactivatedAt" = now()
        WHERE "id" = ${PLATFORM_SWITCH_ID} AND "active" = true`;
      if (changed === 0) return null;
      return this.audit.recordInTransaction(tx, tenantId, {
        eventType: AUDIT_EVENT_TYPES.KILL_SWITCH_DEACTIVATED,
        actor: { type: 'system', id: caller },
        data: {
          killSwitchId: PLATFORM_SWITCH_ID,
          scope: 'TENANT',
          targetId: PLATFORM_SWITCH_TARGET,
        },
      });
    });
    result?.();
    if (result !== null) await this.epochs?.bumpTenant(tenantId);
    return result !== null;
  }
}
