import { Injectable } from '@nestjs/common';
import { AuditService } from '../audit/audit.service';
import {
  AUDIT_EVENT_TYPES,
  type AuditEventType,
} from '../audit/audit-event-types';
import { throwFailClosed } from '../common/fail-closed/fail-closed';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { StaffAuditService } from './audit/staff-audit.service';
import { badge, type StaffPrincipal } from './auth/staff-principal';

const VIEW_DEDUPE_MS = 15 * 60 * 1000;

export type TrustActor =
  | Pick<StaffPrincipal, 'staffId' | 'firstName' | 'team' | 'ip' | 'requestId'>
  | 'system';

/**
 * The trust log (spec §11.5): every staff view or action on a workspace is an event in THAT
 * workspace's own audit chain, with actor `{type: 'staff', id, display: "Ali · Manar Sales"}`.
 * Record opens are written at most once per staff member per workspace per 15 minutes (AC-37).
 * Never internal notes. A failed write fails the staff request (503): no silent staff access.
 */
@Injectable()
export class TrustLogService {
  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly audit: AuditService,
    private readonly staffAudit: StaffAuditService,
  ) {}

  /** The workspaces a person-level event lands in: their personal workspaces (spec §11.5). */
  async personalWorkspacesOf(accountId: string): Promise<string[]> {
    const a = await this.control.account.findUnique({
      where: { id: accountId },
    });
    if (!a) return [];
    const t = await this.control.tenant.findMany({
      where: {
        kind: 'PERSONAL',
        ownerIssuer: a.issuer,
        ownerSubject: a.subject,
        status: { in: ['ACTIVE', 'SUSPENDED'] },
      },
      select: { id: true },
    });
    return t.map((x) => x.id);
  }

  async recordView(
    s: StaffPrincipal,
    tenantId: string,
    scope: 'person' | 'org',
  ): Promise<void> {
    const since = new Date(Date.now() - VIEW_DEDUPE_MS);
    const recent = await this.control.staffAuditEvent.findFirst({
      where: {
        staffId: s.staffId,
        action: 'trust.record_viewed',
        targetId: tenantId,
        at: { gt: since },
      },
      select: { seq: true },
    });
    if (recent) return;
    await this.write(s, tenantId, AUDIT_EVENT_TYPES.STAFF_RECORD_VIEWED, {
      scope,
    });
    await this.staffAudit.append({
      staffId: s.staffId,
      action: 'trust.record_viewed',
      targetType: 'TENANT',
      targetId: tenantId,
      data: { scope },
      ip: s.ip,
      requestId: s.requestId,
    });
  }

  async recordPii(
    s: StaffPrincipal,
    tenantId: string,
    fields: string[],
  ): Promise<void> {
    await this.write(s, tenantId, AUDIT_EVENT_TYPES.STAFF_PII_VIEWED, {
      fields,
    });
  }

  async recordAction(
    s: TrustActor,
    tenantId: string,
    a: { action: string; reasonCategory?: string; fields?: string[] },
  ): Promise<void> {
    await this.write(s, tenantId, AUDIT_EVENT_TYPES.STAFF_ACTION, a);
  }

  /** `scope`: `self` (their own account), `member` (a member of this company), `workspace`. */
  async recordRestriction(
    s: TrustActor,
    tenantId: string,
    r: {
      change:
        'warned' | 'suspended' | 'banned' | 'lifted' | 'unbanned' | 'expired';
      category: string;
      scope: 'self' | 'member' | 'workspace';
      until?: Date | null;
    },
  ): Promise<void> {
    await this.write(s, tenantId, AUDIT_EVENT_TYPES.STAFF_RESTRICTION, {
      ...r,
      until: r.until?.toISOString() ?? null,
    });
  }

  private async write(
    s: TrustActor,
    tenantId: string,
    eventType: AuditEventType,
    data: Record<string, unknown>,
  ) {
    try {
      const db = await this.tenants.getClient(tenantId);
      await this.audit.record(db, tenantId, {
        eventType,
        actor:
          s === 'system'
            ? { type: 'system', id: 'manar-trust-and-safety' }
            : { type: 'staff', id: s.staffId, display: badge(s) },
        data,
      });
    } catch (error) {
      throwFailClosed('trust-log', error);
    }
  }
}
