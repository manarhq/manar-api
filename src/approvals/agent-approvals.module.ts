import { Module } from '@nestjs/common';
import { AgentMtlsGuardModule } from '../agent-mtls/agent-mtls-guard.module';
import { ApprovalsModule } from './approvals.module';
import { AgentApprovalsController } from './agent-approvals.controller';

/** The agent-facing `GET /agent/v1/approvals/:id` HTTP surface — split from `ApprovalsModule` for the same reason `ToolInvokeModule` is. Imported only into `AgentMtlsAppModule`. */
@Module({
  imports: [AgentMtlsGuardModule, ApprovalsModule],
  controllers: [AgentApprovalsController],
})
export class AgentApprovalsModule {}
