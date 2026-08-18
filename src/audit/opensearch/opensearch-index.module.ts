import { Module } from '@nestjs/common';
import { OpenSearchIndexService } from './opensearch-client.service';
import { AuditReindexService } from './audit-reindex.service';

/**
 * The OpenSearch client + reindex logic, without the live Kafka consumer
 * (`AuditIndexerModule` below) — this is all `pnpm manar audit:reindex`
 * (`CliModule`, which never runs a background Kafka consumer) needs.
 * Deliberately not `@Global()`: only the two places that actually need
 * these providers (`AppModule`, via `AuditIndexerModule`, and `CliModule`)
 * import it.
 */
@Module({
  providers: [OpenSearchIndexService, AuditReindexService],
  exports: [OpenSearchIndexService, AuditReindexService],
})
export class OpenSearchIndexModule {}
