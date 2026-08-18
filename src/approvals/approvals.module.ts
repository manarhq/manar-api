import { Module } from '@nestjs/common';
import { TasksModule } from '../tasks/tasks.module';
import { PolicyModule } from '../policy/policy.module';
import { RiskModule } from '../risk/risk.module';
import { ApprovalRequestService } from './approval-request.service';
import { GrantService } from './grant.service';

/**
 * Providers-only (no controller — see `ApprovalsHttpModule`/
 * `AgentApprovalsModule` for the two HTTP surfaces), mirroring
 * `PolicyModule`/`TasksModule`'s split. Needed by three different
 * consumers that must never see three different implementations of
 * "create/read an ApprovalRequest" or "issue/validate a grant": the
 * human-facing `/approvals` app, the agent-facing `/agent/v1/*` app
 * (`ToolInvokeModule` for creating requests + validating retried grants,
 * `AgentApprovalsModule` for polling), and the separate Temporal worker
 * process's Activities (`src/worker.main.ts` bootstraps this exact same
 * module to build them).
 */
@Module({
  imports: [TasksModule, PolicyModule, RiskModule],
  providers: [ApprovalRequestService, GrantService],
  exports: [ApprovalRequestService, GrantService],
})
export class ApprovalsModule {}
