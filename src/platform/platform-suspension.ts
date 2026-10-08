import { Injectable } from '@nestjs/common';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';

/** The tenant-local profile that owns kill switches set by the platform API (not a person). */
export const PLATFORM_SUBJECT = 'platform:manar-fleet';
export const SUSPEND_REASON = 'tenant_suspended';

/**
 * Makes a platform suspend effective on the decision path in every process at once (ADR-0010):
 * a TENANT-scope kill switch in the tenant database, which `KillSwitchService.checkAll` reads per
 * request in every API replica and the worker. Only the platform's own switch is ever released:
 * a tenant switch a human set (or re-set) stays.
 */
@Injectable()
export class PlatformSuspension {
  constructor(private readonly audit: AuditService) {}

  private async platformProfile(db: TenantPrismaClient): Promise<string> {
    const p = await db.userProfile.upsert({
      where: { keycloakSubject: PLATFORM_SUBJECT },
      create: {
        keycloakSubject: PLATFORM_SUBJECT,
        email: '',
        displayName: 'Platform (manar-fleet)',
      },
      update: {},
    });
    return p.id;
  }

  /** Returns false when a tenant switch was already active (left untouched). */
  async engage(
    db: TenantPrismaClient,
    tenantId: string,
    caller: string,
  ): Promise<boolean> {
    const existing = await db.killSwitch.findFirst({
      where: { scope: 'TENANT', targetId: null },
    });
    if (existing?.active) return false;
    const by = await this.platformProfile(db);
    const data = {
      active: true,
      reason: SUSPEND_REASON,
      activatedBy: by,
      activatedAt: new Date(),
      deactivatedBy: null,
      deactivatedAt: null,
    };
    const row = existing
      ? await db.killSwitch.update({ where: { id: existing.id }, data })
      : await db.killSwitch.create({
          data: { scope: 'TENANT', targetId: null, ...data },
        });
    await this.audit.recordSafely(db, tenantId, {
      eventType: AUDIT_EVENT_TYPES.KILL_SWITCH_ACTIVATED,
      actor: { type: 'system', id: caller },
      data: {
        killSwitchId: row.id,
        scope: 'TENANT',
        targetId: null,
        reason: SUSPEND_REASON,
      },
    });
    return true;
  }

  /** Releases the tenant switch only if the platform set it and nobody re-set it since. */
  async release(
    db: TenantPrismaClient,
    tenantId: string,
    caller: string,
  ): Promise<boolean> {
    const by = await this.platformProfile(db);
    const res = await db.killSwitch.updateMany({
      where: {
        scope: 'TENANT',
        targetId: null,
        active: true,
        activatedBy: by,
        reason: SUSPEND_REASON,
      },
      data: { active: false, deactivatedBy: by, deactivatedAt: new Date() },
    });
    if (res.count === 0) return false;
    await this.audit.recordSafely(db, tenantId, {
      eventType: AUDIT_EVENT_TYPES.KILL_SWITCH_DEACTIVATED,
      actor: { type: 'system', id: caller },
      data: { scope: 'TENANT', targetId: null, reason: SUSPEND_REASON },
    });
    return true;
  }
}
