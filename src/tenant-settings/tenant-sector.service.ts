import { Injectable } from '@nestjs/common';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';

export type TenantSectorValue = 'COMMERCIAL' | 'GOVERNMENT';

/**
 * Staff records a workspace's sector (legacy Company workspaces have none). The audit event is
 * written first and the change is refused if it cannot be: the sector decides the AI default.
 * Government: AI off, recorded as an explicit choice. Commercial: sector only; `ai:default-on` or
 * the owner's own opt-in turns AI on.
 */
@Injectable()
export class TenantSectorService {
  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly audit: AuditService,
  ) {}

  async set(
    tenantId: string,
    sector: TenantSectorValue,
    actor: string,
  ): Promise<void> {
    const client = await this.tenants.getClient(tenantId);
    await this.audit.record(client, tenantId, {
      eventType: AUDIT_EVENT_TYPES.TENANT_SECTOR_SET,
      actor: { type: 'system', id: actor },
      data: { sector },
    });
    await this.control.tenant.update({
      where: { id: tenantId },
      data:
        sector === 'GOVERNMENT'
          ? {
              sector,
              allowExternalAi: false,
              allowExternalAiChosen: true,
              aiDefaultNoticePending: false,
              aiOptInNoticePending: false,
            }
          : { sector },
    });
  }
}
