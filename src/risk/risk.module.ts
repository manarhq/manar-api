import { Module } from '@nestjs/common';
import { TasksModule } from '../tasks/tasks.module';
import { ToolsModule } from '../tools/tools.module';
import { AiAdvisoryModule } from '../ai-advisory/ai-advisory.module';
import { RiskEngine } from './risk-engine.service';

/** Providers-only (no controller) — `RiskEngine` is only ever consumed by `AuthorizationService` on the agent-facing mTLS app (`AgentAuthorizeModule`), never directly reachable via any HTTP route of its own. Depends on `TasksModule` for `TasksService.getAncestorChain` (reused, not re-derived), since Phase 7b `ToolsModule` for `ToolRegistryService` (real per-action risk metadata), and since Phase 10b `AiAdvisoryModule` for `AiAdvisoryClient` (activates `aiAdvisoryScore`) — see `RiskEngine`'s own doc comment. */
@Module({
  imports: [TasksModule, ToolsModule, AiAdvisoryModule],
  providers: [RiskEngine],
  exports: [RiskEngine],
})
export class RiskModule {}
