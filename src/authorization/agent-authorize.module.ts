import { Module } from '@nestjs/common';
import { AgentMtlsGuardModule } from '../agent-mtls/agent-mtls-guard.module';
import { TasksModule } from '../tasks/tasks.module';
import { AuthorizationModule } from './authorization.module';
import { AuthorizationService } from './authorization.service';
import { AuthorizeController } from './authorize.controller';

/**
 * The agent-facing `POST /agent/v1/authorize` HTTP surface. Separate from
 * `AuthorizationModule` (the `@Global()`, controller-free
 * `OpenFgaClientService`/`TaskGrantSyncService` module shared by both Nest
 * applications) because `AuthorizationService`/`AuthorizeController` only
 * ever belong on the mTLS app — imported only into `AgentMtlsAppModule`.
 */
@Module({
  imports: [AgentMtlsGuardModule, TasksModule, AuthorizationModule],
  providers: [AuthorizationService],
  controllers: [AuthorizeController],
  exports: [AuthorizationService],
})
export class AgentAuthorizeModule {}
