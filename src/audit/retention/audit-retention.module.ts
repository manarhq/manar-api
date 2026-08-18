import { Module } from '@nestjs/common';
import { AuditRetentionService } from './audit-retention.service';

/**
 * `AuditRetentionService` alone — imported by `WorkerAppModule` (via
 * `AuditRetentionActivitiesFactory`, `src/temporal/activities/audit-retention.activities.ts`),
 * the only place this phase's retention logic actually runs. Not imported
 * by either Fastify HTTP app: there is deliberately no API path that
 * triggers retention (Section 48 — retention only ever runs via
 * `AuditRetentionWorkflow`).
 */
@Module({
  providers: [AuditRetentionService],
  exports: [AuditRetentionService],
})
export class AuditRetentionModule {}
