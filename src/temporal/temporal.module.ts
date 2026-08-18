import { Global, Module } from '@nestjs/common';
import { TemporalClientService } from './temporal-client.service';

/**
 * `@Global()`, same posture as `DatabaseModule`/`AuthorizationModule` — a
 * cross-cutting infrastructure client every module that needs to
 * start/signal `ApprovalWorkflow` depends on. Imported explicitly into
 * both `AppModule` and `AgentMtlsAppModule` (each `NestFactory.create()`
 * call gets its own DI container — "global" only means "global within one
 * application's module graph", same caveat `AgentMtlsAppModule`'s own doc
 * comment already documents for `DatabaseModule`).
 */
@Global()
@Module({
  providers: [TemporalClientService],
  exports: [TemporalClientService],
})
export class TemporalModule {}
