import { Injectable } from '@nestjs/common';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import { GrantService } from '../../approvals/grant.service';
import type {
  ApprovalActivities,
  ExpireApprovalRequestInput,
  FinalizeApprovalDecisionInput,
  FinalizeApprovalDecisionResult,
} from './approval-activities.interface';

/**
 * The real implementation behind `ApprovalActivities` (Section 28: all
 * I/O — DB, crypto — lives here, never in `approval.workflow.ts`). Runs
 * only inside the separate worker process (`src/worker.main.ts`), never
 * inside the Fastify HTTP server's event loop and never inside the
 * workflow's own deterministic sandbox.
 *
 * A factory (`build()`), not a class Temporal's `Worker.create` invokes
 * directly — `Worker.create({ activities })` wants a plain object mapping
 * activity name -> async function, not a class instance with methods, so
 * `src/worker.main.ts` resolves this from the worker's own bootstrapped
 * Nest application context and calls `build()` once to get that object.
 * The actual logic underneath (`GrantService`) is the *exact same*
 * injectable `POST /agent/v1/tools/invoke`'s grant-validation path also
 * uses — Nest DI just gives the worker's own application context its own
 * instance of it, resolving each call's tenant-scoped Prisma client the
 * same way every other tenant-scoped service in this codebase does
 * (`TenantDatabaseManager.getClient`).
 */
@Injectable()
export class ApprovalActivitiesFactory {
  constructor(
    private readonly grantService: GrantService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

  build(): ApprovalActivities {
    return {
      finalizeApprovalDecision: async (
        input: FinalizeApprovalDecisionInput,
      ): Promise<FinalizeApprovalDecisionResult> => {
        const tenantClient = await this.tenantDatabaseManager.getClient(
          input.tenantId,
        );
        return this.grantService.finalizeDecision(tenantClient, {
          tenantId: input.tenantId,
          approvalRequestId: input.approvalRequestId,
          decision: input.decision,
          approverId: input.approverId,
          reason: input.reason,
        });
      },

      expireApprovalRequest: async (
        input: ExpireApprovalRequestInput,
      ): Promise<void> => {
        const tenantClient = await this.tenantDatabaseManager.getClient(
          input.tenantId,
        );
        await this.grantService.expire(tenantClient, input.approvalRequestId);
      },
    };
  }
}
