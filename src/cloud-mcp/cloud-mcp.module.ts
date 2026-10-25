import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { cloudMcpBodyLimit } from './cloud-mcp-body-limit.middleware';
import { cloudMcpSettings } from './cloud-mcp.config';
import { AgentRuntimeController } from '../agent-runtime/agent-runtime.controller';
import { AgentTaskAccessService } from '../agent-runtime/agent-task-access.service';
import { ToolManifestService } from '../agent-runtime/tool-manifest.service';
import { ApprovalsModule } from '../approvals/approvals.module';
import { AuthorizationModule } from '../authorization/authorization.module';
import { AuthorizationService } from '../authorization/authorization.service';
import { KillSwitchesModule } from '../kill-switches/kill-switches.module';
import { CatalogModule } from '../platform/catalog.module';
import { PolicyModule } from '../policy/policy.module';
import { RiskModule } from '../risk/risk.module';
import { TasksModule } from '../tasks/tasks.module';
import { TemporalModule } from '../temporal/temporal.module';
import { ToolInvocationService } from '../tools/tool-invocation.service';
import { ToolsModule } from '../tools/tools.module';
import { CloudAgentsController } from './cloud-agents.controller';
import { CloudAgentsService } from './cloud-agents.service';
import { CloudMcpAuthGuard } from './cloud-mcp-auth.guard';
import { CloudMcpController } from './cloud-mcp.controller';

/**
 * Cloud agents on the HTTP app (docs/cloud-agents.md): the public OAuth MCP
 * endpoint and the admin API that connects agents. The governed MCP server
 * and its pipeline (`AgentRuntimeController.serveMcp`, `ToolInvocationService`,
 * `AuthorizationService`) are providers here, built from the same
 * providers-only modules the mTLS app uses, so no `/agent/v1/*` route is
 * mounted on this app: one governed MCP server, two doors.
 */
@Module({
  imports: [
    TasksModule,
    AuthorizationModule,
    PolicyModule,
    RiskModule,
    KillSwitchesModule,
    CatalogModule,
    ToolsModule,
    ApprovalsModule,
    TemporalModule,
  ],
  controllers: [CloudMcpController, CloudAgentsController],
  providers: [
    CloudMcpAuthGuard,
    CloudAgentsService,
    AuthorizationService,
    ToolInvocationService,
    AgentTaskAccessService,
    ToolManifestService,
    AgentRuntimeController,
  ],
})
export class CloudMcpModule implements NestModule {
  constructor(private readonly config: ConfigService<AppConfig, true>) {}

  configure(consumer: MiddlewareConsumer): void {
    consumer
      .apply(cloudMcpBodyLimit(cloudMcpSettings(this.config).maxBodyBytes))
      .forRoutes(CloudMcpController);
  }
}
