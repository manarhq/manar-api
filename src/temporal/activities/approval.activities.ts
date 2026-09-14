import { Injectable } from '@nestjs/common';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import { GrantService } from '../../approvals/grant.service';
import { AiAdvisoryClient } from '../../ai-advisory/ai-advisory-client.service';
import { ToolRegistryService } from '../../tools/tool-registry.service';
import type {
  ApprovalActivities,
  AttachRiskAdvisoryInput,
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
    // Phase 1 (ADR-004): the advisory client lives HERE, in the worker
    // process, and nowhere on the synchronous decision path. See
    // `src/authorization/decision-path-dependencies.spec.ts`, which fails if
    // it ever becomes reachable from the PDP's import graph again.
    private readonly aiAdvisoryClient: AiAdvisoryClient,
    private readonly toolRegistry: ToolRegistryService,
  ) {}

  build(): ApprovalActivities {
    return {
      attachRiskAdvisory: async (
        input: AttachRiskAdvisoryInput,
      ): Promise<void> => {
        const tenantClient = await this.tenantDatabaseManager.getClient(
          input.tenantId,
        );
        const approval = await tenantClient.approvalRequest.findUnique({
          where: { id: input.approvalRequestId },
        });
        if (!approval) return;

        // The resolved ToolAction classification is not decoration: it is what
        // lets `AiAdvisoryClient.analyzeRisk` independently refuse to send a
        // RESTRICTED action's context to an external provider, regardless of
        // the tenant's `allowExternalAi` flag. Dropping it while relocating
        // this call would have quietly weakened a data-residency control, so
        // it is resolved here exactly as `RiskEngine` used to resolve it.
        const registered = await this.toolRegistry.findToolAction(
          tenantClient,
          approval.toolId,
          approval.actionId,
        );

        const advisory = await this.aiAdvisoryClient.analyzeRisk({
          actionDescription: `Agent action: ${approval.toolId}.${approval.actionId} on resource "${approval.resource}"`,
          context: `taskId=${approval.taskId} riskCeiling=${approval.taskRiskCeiling ?? 'unknown'} deterministicRiskScore=${approval.deterministicRiskScore ?? approval.riskScore}`,
          tenantId: input.tenantId,
          classification: registered?.action.classification,
        });

        // `null` covers every unavailability path the client folds together —
        // unreachable, timed out, circuit open, or a zero-confidence
        // fail-secure marker. All of them mean the approver has no AI signal,
        // and the record must say so rather than leave a NULL score that reads
        // as "low risk".
        if (!advisory) return;

        const existing = Array.isArray(approval.riskReasonCodes)
          ? (approval.riskReasonCodes as unknown[]).filter(
              (code): code is string => typeof code === 'string',
            )
          : [];
        // Idempotent: re-running this activity must not append a second copy
        // of the advisory codes. Temporal retries it, and `maximumAttempts: 2`
        // means a retry is a normal occurrence, not an exceptional one.
        const deterministicCodes = existing.filter(
          (code) => !code.startsWith('ai_advisory'),
        );

        await tenantClient.approvalRequest.update({
          where: { id: approval.id },
          data: {
            aiAdvisoryScore: advisory.score,
            advisoryUnavailable: false,
            riskReasonCodes: [
              ...deterministicCodes,
              `ai_advisory_score:${advisory.score}`,
              `ai_advisory_recommended_action:${advisory.recommendedAction}`,
              ...advisory.signals.map(
                (signal) => `ai_advisory_signal:${signal}`,
              ),
            ],
          },
        });
      },

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
