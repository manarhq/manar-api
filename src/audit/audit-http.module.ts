import { Module } from '@nestjs/common';
import { AiAdvisoryModule } from '../ai-advisory/ai-advisory.module';
import { ToolsModule } from '../tools/tools.module';
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
 *
 * Phase 10c adds `AiAdvisoryModule` (`AiAdvisoryClient`, for
 * `AuditSearchService.investigateAudit`) and `ToolsModule`
 * (`ToolRegistryService`, to resolve retrieved events' classification) —
 * same two-import shape `PolicyModule`/`IncidentsModule` establish for the
 * identical dependency pair.
 */
@Module({
  imports: [AuditModule, OpenSearchIndexModule, AiAdvisoryModule, ToolsModule],
  controllers: [AuditController],
  providers: [AuditSearchService],
})
export class AuditHttpModule {}
