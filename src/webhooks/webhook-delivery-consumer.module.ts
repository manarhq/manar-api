import { Module } from '@nestjs/common';
import { TemporalModule } from '../temporal/temporal.module';
import { WebhookDeliveryConsumerService } from './webhook-delivery-consumer.service';

/**
 * The Kafka-consuming half of Phase 12a's webhooks feature — split out
 * from `WebhooksModule` (the CRUD/delivery-attempt services) the same way
 * `AuditIndexerModule` is split from `AuditModule`: this is a background
 * consumer with its own lifecycle, imported once into `AppModule` (the
 * human-facing process — mirroring exactly where `AuditIndexerModule`
 * itself is mounted), never into `AgentMtlsAppModule`/`WorkerAppModule`.
 * Explicitly imports `TemporalModule` (even though it's `@Global()`) for
 * the same "visible from this file alone" reason `AiAdvisoryModule` now
 * imports `DatabaseModule`.
 */
@Module({
  imports: [TemporalModule],
  providers: [WebhookDeliveryConsumerService],
})
export class WebhookDeliveryConsumerModule {}
