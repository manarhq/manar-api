import { Injectable, Logger } from '@nestjs/common';
import type { AuditActor } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';

/** Audit a growth event in the workspace it concerns; never fails the caller. */
@Injectable()
export class GrowthAuditService {
  private readonly logger = new Logger(GrowthAuditService.name);

  constructor(
    private readonly audit: AuditService,
    private readonly tenants: TenantDatabaseManager,
  ) {}

  async record(
    tenantId: string,
    eventType: string,
    actor: AuditActor,
    data: Record<string, unknown>,
  ): Promise<void> {
    try {
      const client = await this.tenants.getClient(tenantId);
      await this.audit.recordSafely(client, tenantId, {
        eventType: eventType as never,
        actor,
        data,
      });
    } catch (error) {
      this.logger.warn(
        `audit ${eventType} failed for ${tenantId}: ${String(error)}`,
      );
    }
  }
}
