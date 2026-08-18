import { Injectable } from '@nestjs/common';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import { AuditRetentionService } from '../../audit/retention/audit-retention.service';
import type {
  AuditRetentionActivities,
  PruneAuditEventsInput,
  PruneAuditEventsResult,
} from './audit-retention-activities.interface';

/**
 * The real implementation behind `AuditRetentionActivities` — mirrors
 * `ApprovalActivitiesFactory`'s own shape exactly (a factory, not a class
 * Temporal's `Worker.create` invokes directly; see that file's doc
 * comment for why). Runs only inside the separate worker process
 * (`src/worker.main.ts`).
 */
@Injectable()
export class AuditRetentionActivitiesFactory {
  constructor(
    private readonly auditRetentionService: AuditRetentionService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

  build(): AuditRetentionActivities {
    return {
      pruneAuditEvents: async (
        input: PruneAuditEventsInput,
      ): Promise<PruneAuditEventsResult> => {
        const tenantClient = await this.tenantDatabaseManager.getClient(
          input.tenantId,
        );
        return this.auditRetentionService.pruneTenantAuditEvents(
          tenantClient,
          input,
        );
      },
    };
  }
}
