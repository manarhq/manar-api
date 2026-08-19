import { Module } from '@nestjs/common';
import { OpenSearchIndexService } from './opensearch-client.service';
import { AuditReindexService } from './audit-reindex.service';

/**
 * The OpenSearch client + reindex logic, without the live Kafka consumer
 * (`AuditIndexerModule` below) — this is all `pnpm manar audit:reindex`
 * (`CliModule`, which never runs a background Kafka consumer) needs.
 * Deliberately not `@Global()`: only the places that actually need these
 * providers import it directly — `AppModule` (via `AuditIndexerModule`
 * for the live consumer, and since Phase 11b Part 1, `AuditHttpModule` for
 * `GET /audit`'s `AuditSearchService`) and `CliModule`. Nest dedupes a
 * module imported more than once within the same DI graph, so
 * `AuditIndexerModule` and `AuditHttpModule` both importing this share the
 * one `OpenSearchIndexService` connection, not two.
 */
@Module({
  providers: [OpenSearchIndexService, AuditReindexService],
  exports: [OpenSearchIndexService, AuditReindexService],
})
export class OpenSearchIndexModule {}
