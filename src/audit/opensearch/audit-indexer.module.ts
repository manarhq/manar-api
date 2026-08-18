import { Module } from '@nestjs/common';
import { OpenSearchIndexModule } from './opensearch-index.module';
import { RedisPubSubModule } from '../live/redis-pubsub.module';
import { AuditIndexerService } from './audit-indexer.service';

/**
 * The real, running Kafka consumer (`AuditIndexerService`) — imported only
 * into `AppModule` (the human-facing HTTP process), not
 * `AgentMtlsAppModule`/`WorkerAppModule`. Only one process needs to run
 * this consumer at all (see `AuditIndexerService`'s own doc comment on why
 * a fresh consumer group per process is safe, not why *multiple
 * concurrently-running* consumers would be wrong — they wouldn't be
 * *incorrect*, just redundant work); `AppModule` is the natural home since
 * `GET /events/live` (the consumer's other output, via Redis) lives there
 * too.
 */
@Module({
  imports: [OpenSearchIndexModule, RedisPubSubModule],
  providers: [AuditIndexerService],
  exports: [AuditIndexerService],
})
export class AuditIndexerModule {}
