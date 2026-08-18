import { Module } from '@nestjs/common';
import { AgentAuthorizeModule } from '../authorization/agent-authorize.module';
import { AgentMtlsGuardModule } from '../agent-mtls/agent-mtls-guard.module';
import { ToolInvokeController } from './tool-invoke.controller';
import { ToolsModule } from './tools.module';

/**
 * The agent-facing `POST /agent/v1/tools/invoke` HTTP surface (Phase 7b).
 * Imported only into `AgentMtlsAppModule`, mirroring `DelegationModule`'s
 * single-app-only shape. Imports `AgentAuthorizeModule` for its exported
 * `AuthorizationService` — this controller calls that *exact* existing
 * pipeline unchanged, never a fork of it.
 */
@Module({
  imports: [AgentMtlsGuardModule, AgentAuthorizeModule, ToolsModule],
  controllers: [ToolInvokeController],
})
export class ToolInvokeModule {}
