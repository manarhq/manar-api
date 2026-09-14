import { Module } from '@nestjs/common';
import { AppConfigModule } from '../config/config.module';
import { DatabaseModule } from '../database/database.module';
import { OpenBaoModule } from '../openbao/openbao.module';
import { TasksModule } from '../tasks/tasks.module';
import { PolicyModule } from '../policy/policy.module';
import { RiskModule } from '../risk/risk.module';
import { ApprovalsModule } from '../approvals/approvals.module';
import { AuditModule } from '../audit/audit.module';
import { AuditRetentionModule } from '../audit/retention/audit-retention.module';
import { KillSwitchesModule } from '../kill-switches/kill-switches.module';
import { WebhooksModule } from '../webhooks/webhooks.module';
import { AiAdvisoryModule } from '../ai-advisory/ai-advisory.module';
import { ToolsModule } from '../tools/tools.module';
import { ApprovalActivitiesFactory } from './activities/approval.activities';
import { AuditRetentionActivitiesFactory } from './activities/audit-retention.activities';
import { WebhookDeliveryActivitiesFactory } from './activities/webhook-delivery.activities';

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
    KillSwitchesModule,
    TasksModule,
    PolicyModule,
    RiskModule,
    // Phase 1 (ADR-004): manar-ai is reached from the WORKER process only.
    // `ApprovalActivitiesFactory.attachRiskAdvisory` annotates an approval for
    // the human approver, off the synchronous decision path. The HTTP app's
    // authorize path must never import these — enforced by
    // `src/authorization/decision-path-dependencies.spec.ts`.
    AiAdvisoryModule,
    ToolsModule,
    ApprovalsModule,
    AuditRetentionModule,
    WebhooksModule,
  ],
  providers: [
    ApprovalActivitiesFactory,
    AuditRetentionActivitiesFactory,
    WebhookDeliveryActivitiesFactory,
  ],
  exports: [
    ApprovalActivitiesFactory,
    AuditRetentionActivitiesFactory,
    WebhookDeliveryActivitiesFactory,
  ],
})
export class WorkerAppModule {}
