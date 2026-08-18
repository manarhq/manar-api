import { Module } from '@nestjs/common';
import { AgentMtlsGuardModule } from '../agent-mtls/agent-mtls-guard.module';
import { AgentsModule } from '../agents/agents.module';
import { AuthorizationModule } from '../authorization/authorization.module';
import { TasksModule } from '../tasks/tasks.module';
import { DelegationController } from './delegation.controller';
import { DelegationService } from './delegation.service';

/**
 * The agent-facing `POST /agent/v1/tasks/:id/delegate` HTTP surface.
 * Imported only into `AgentMtlsAppModule`. `AgentsModule` here is the
 * Phase 5 services-only module (see its doc comment) — reused for
 * `AgentsService.createAgent`/`createEnrollmentToken`, never a second
 * instance, and never dragging `AgentsController`'s JWT-gated routes onto
 * this mTLS-only listener.
 */
@Module({
  imports: [
    AgentMtlsGuardModule,
    TasksModule,
    AgentsModule,
    AuthorizationModule,
  ],
  providers: [DelegationService],
  controllers: [DelegationController],
})
export class DelegationModule {}
