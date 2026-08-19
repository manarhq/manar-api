import { Module } from '@nestjs/common';
import { AuditModule } from './audit.module';
import { AuditController } from './audit.controller';
import { AuditSearchService } from './audit-search.service';
import { OpenSearchIndexModule } from './opensearch/opensearch-index.module';

/**
 * The human-facing `/audit` HTTP surface — split from `AuditModule`
 * (providers-only, `@Global()`) for the same reason `PolicyHttpModule`/
 * `TasksHttpModule` are. Imported only into `AppModule`.
 *
 * Phase 11b Part 1 adds `OpenSearchIndexModule` (for `GET /audit`'s real
 * search backend — `AuditSearchService`) — a second consumer of that
 * module alongside `AuditIndexerModule`/`CliModule`, all sharing the one
 * `OpenSearchIndexService` connection within this process's DI container.
 */
@Module({
  imports: [AuditModule, OpenSearchIndexModule],
  controllers: [AuditController],
  providers: [AuditSearchService],
})
export class AuditHttpModule {}
