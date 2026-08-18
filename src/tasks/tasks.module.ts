import { Module } from '@nestjs/common';
import { AuthorizationModule } from '../authorization/authorization.module';
import { TasksService } from './tasks.service';

/**
 * Providers-only (no controller) — see `AgentsModule`'s doc comment for
 * why this split exists: `TasksService` is needed by both `TasksHttpModule`
 * (human-facing `/tasks`, `AppModule` only) and the agent-facing mTLS
 * surfaces (`AuthorizationService`'s ancestor walk, `DelegationService`'s
 * subset check and child-task creation — `AgentMtlsAppModule`), and only
 * the former should ever expose a `JwtAuthGuard`-gated route.
 */
@Module({
  imports: [AuthorizationModule],
  providers: [TasksService],
  exports: [TasksService],
})
export class TasksModule {}
