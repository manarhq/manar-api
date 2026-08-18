import { Module } from '@nestjs/common';
import { AppConfigModule } from '../config/config.module';
import { DatabaseModule } from '../database/database.module';
import { OpenBaoModule } from '../openbao/openbao.module';
import { TasksModule } from '../tasks/tasks.module';
import { PolicyModule } from '../policy/policy.module';
import { RiskModule } from '../risk/risk.module';
import { ApprovalsModule } from '../approvals/approvals.module';
import { AuditModule } from '../audit/audit.module';
import { ApprovalActivitiesFactory } from './activities/approval.activities';

/**
 * Root module for the separate Temporal worker process
 * (`src/worker.main.ts`, `pnpm worker`) — a plain Nest *application
 * context* (`NestFactory.createApplicationContext`, no HTTP listener of
 * any kind), bootstrapped purely to get real, DI-wired instances of the
 * exact same providers the two Fastify apps use
 * (`TenantDatabaseManager`/`PolicyEngine`/`RiskEngine`/`TasksService`/
 * `GrantService`) — never a second, hand-rolled copy of "how to resolve a
 * tenant's Prisma client" or "how re-evaluation works." See
 * `ApprovalActivitiesFactory` for how these become the plain-function
 * `activities` object Temporal's `Worker.create` wants.
 *
 * Deliberately does *not* import `LoggingModule`/`AuthModule`/
 * `AgentsHttpModule`/any controller-bearing module — this process never
 * serves HTTP traffic, only polls Temporal's task queue.
 */
@Module({
  imports: [
    AppConfigModule,
    DatabaseModule,
    OpenBaoModule,
    AuditModule,
    TasksModule,
    PolicyModule,
    RiskModule,
    ApprovalsModule,
  ],
  providers: [ApprovalActivitiesFactory],
  exports: [ApprovalActivitiesFactory],
})
export class WorkerAppModule {}
