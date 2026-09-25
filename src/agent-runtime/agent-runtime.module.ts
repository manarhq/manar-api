import { Module } from '@nestjs/common';
import { AgentMtlsGuardModule } from '../agent-mtls/agent-mtls-guard.module';
import { AiAdvisoryModule } from '../ai-advisory/ai-advisory.module';
import { TasksModule } from '../tasks/tasks.module';
import { AgentTaskAccessService } from './agent-task-access.service';
import { LlmBudgetStore } from './llm-budget.store';
import { LlmProxyController } from './llm-proxy.controller';
import { LlmProxyService } from './llm-proxy.service';
import { LlmUpstreamClient } from './llm-upstream.client';

/**
 * The agent runtime surface on the mTLS listener (ADR-0002): the LLM proxy,
 * the per-task tool manifest and the governed MCP server. Imported only by
 * `AgentMtlsAppModule`.
 */
@Module({
  imports: [AgentMtlsGuardModule, AiAdvisoryModule, TasksModule],
  controllers: [LlmProxyController],
  providers: [
    AgentTaskAccessService,
    LlmBudgetStore,
    LlmUpstreamClient,
    LlmProxyService,
  ],
})
export class AgentRuntimeModule {}
