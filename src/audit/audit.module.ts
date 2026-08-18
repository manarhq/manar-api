import { Global, Module } from '@nestjs/common';
import { AuditService } from './audit.service';
import { KafkaPublisherService } from './kafka-publisher.service';

/**
 * `@Global()`, same posture as `DatabaseModule`/`TemporalModule` — every
 * domain module this phase retrofits (`AgentsModule`, `TasksModule`,
 * `DelegationModule`, `AuthorizationModule`, `ToolInvokeModule`,
 * `ApprovalsModule`, `PolicyModule`) needs `AuditService`. Imported
 * explicitly into all three application root modules
 * (`AppModule`/`AgentMtlsAppModule`/`WorkerAppModule` — see
 * `src/temporal/worker-app.module.ts`'s own doc comment for why the worker
 * process needs it too: `GrantService.finalizeDecision`'s approval-decision/
 * grant-issued events happen there, not in either HTTP process) — each
 * `NestFactory.create()`/`createApplicationContext()` call gets its own DI
 * container, and therefore its own `KafkaPublisherService` producer
 * connection ("global" only ever means "global within one application's
 * module graph", the same caveat every other `@Global()` module in this
 * codebase documents).
 */
@Global()
@Module({
  providers: [KafkaPublisherService, AuditService],
  exports: [AuditService],
})
export class AuditModule {}
