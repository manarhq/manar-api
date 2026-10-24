import { Module } from '@nestjs/common';
import { AgentMtlsGuardModule } from '../agent-mtls/agent-mtls-guard.module';
import { TasksModule } from '../tasks/tasks.module';
import { PolicyModule } from '../policy/policy.module';
import { RiskModule } from '../risk/risk.module';
import { KillSwitchesModule } from '../kill-switches/kill-switches.module';
import { CatalogModule } from '../platform/catalog.module';
import { AuthorizationModule } from './authorization.module';
import { AuthorizationService } from './authorization.service';
import { AuthorizeController } from './authorize.controller';

/**
 * The agent-facing `POST /agent/v1/authorize` HTTP surface. Separate from
 * `AuthorizationModule` (the `@Global()`, controller-free
 * `OpenFgaClientService`/`TaskGrantSyncService` module shared by both Nest
 * applications) because `AuthorizationService`/`AuthorizeController` only
 * ever belong on the mTLS app — imported only into `AgentMtlsAppModule`.
 * `PolicyModule`/`RiskModule` (Phase 6) are imported here for the exact
 * same reason: `PolicyEngine`/`RiskEngine` are only ever consumed by
 * `AuthorizationService`'s pipeline on this listener, never on the
 * human-facing one.
 */
@Module({
  imports: [
    AgentMtlsGuardModule,
    TasksModule,
    AuthorizationModule,
    PolicyModule,
    RiskModule,
    KillSwitchesModule,
    CatalogModule,
  ],
  providers: [AuthorizationService],
  controllers: [AuthorizeController],
  exports: [AuthorizationService],
})
export class AgentAuthorizeModule {}
