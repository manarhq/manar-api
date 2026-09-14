import { Module } from '@nestjs/common';
import { TasksModule } from '../tasks/tasks.module';
import { ToolsModule } from '../tools/tools.module';
import { RiskEngine } from './risk-engine.service';

/** Providers-only (no controller) — `RiskEngine` is only ever consumed by `AuthorizationService` on the agent-facing mTLS app (`AgentAuthorizeModule`), never directly reachable via any HTTP route of its own. Depends on `TasksModule` for `TasksService.getAncestorChain` (reused, not re-derived), since Phase 7b `ToolsModule` for `ToolRegistryService` (real per-action risk metadata). It deliberately does **not** import `AiAdvisoryModule`: ADR-004 keeps manar-ai off the synchronous decision path, and `src/authorization/decision-path-dependencies.spec.ts` fails if that import returns. The advisory is fetched off the decision path by `RiskAdvisoryService` and attached to the ApprovalRequest for the human approver. */
@Module({
  imports: [TasksModule, ToolsModule],
  providers: [RiskEngine],
  exports: [RiskEngine],
})
export class RiskModule {}
