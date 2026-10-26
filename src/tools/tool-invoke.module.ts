import { Module } from '@nestjs/common';
import { AgentAuthorizeModule } from '../authorization/agent-authorize.module';
import { AgentMtlsGuardModule } from '../agent-mtls/agent-mtls-guard.module';
import { ApprovalsModule } from '../approvals/approvals.module';
import { TemporalModule } from '../temporal/temporal.module';
import { ToolInvokeController } from './tool-invoke.controller';
import { AuthorizeController } from '../authorization/authorize.controller';
import { ToolInvocationService } from './tool-invocation.service';
import { ToolsModule } from './tools.module';

/**
 * The agent-facing `POST /agent/v1/tools/invoke` HTTP surface (Phase 7b).
 * Imported only into `AgentMtlsAppModule`, mirroring `DelegationModule`'s
 * single-app-only shape. Imports `AgentAuthorizeModule` for its exported
 * `AuthorizationService` — this controller calls that *exact* existing
 * pipeline unchanged, never a fork of it. Phase 8 adds `ApprovalsModule`
 * (creating an `ApprovalRequest` on `APPROVAL_REQUIRED`, validating a
 * retried `grantToken`) and `TemporalModule` (starting `ApprovalWorkflow`)
 * — see docs/approvals.md.
 */
@Module({
  imports: [
    AgentMtlsGuardModule,
    AgentAuthorizeModule,
    ToolsModule,
    ApprovalsModule,
    TemporalModule,
  ],
  // AuthorizeController lives here (not in AgentAuthorizeModule) because its
  // APPROVAL_REQUIRED path opens the approval through ToolInvocationService.
  controllers: [ToolInvokeController, AuthorizeController],
  providers: [ToolInvocationService],
  exports: [ToolInvocationService],
})
export class ToolInvokeModule {}
