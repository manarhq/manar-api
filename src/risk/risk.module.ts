import { Module } from '@nestjs/common';
import { TasksModule } from '../tasks/tasks.module';
import { RiskEngine } from './risk-engine.service';

/** Providers-only (no controller) — `RiskEngine` is only ever consumed by `AuthorizationService` on the agent-facing mTLS app (`AgentAuthorizeModule`), never directly reachable via any HTTP route of its own. Depends on `TasksModule` for `TasksService.getAncestorChain` (reused, not re-derived — see `RiskEngine`'s own doc comment). */
@Module({
  imports: [TasksModule],
  providers: [RiskEngine],
  exports: [RiskEngine],
})
export class RiskModule {}
