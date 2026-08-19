import { Module } from '@nestjs/common';
import { OpenBaoModule } from '../openbao/openbao.module';
import { WebhookRegistryService } from './webhook-registry.service';
import { WebhookDeliveryService } from './webhook-delivery.service';

/**
 * Providers-only module (no controller — see `WebhooksHttpModule` for the
 * human-facing admin surface), mirroring `KillSwitchesModule`'s split.
 * Imported into `AppModule` (via `WebhooksHttpModule`), `WorkerAppModule`
 * (`WebhookDeliveryActivitiesFactory` needs `WebhookDeliveryService`), and
 * `WebhookDeliveryConsumerModule` (needs `WebhookRegistryService`'s
 * tenant-scoped lookups... actually the consumer queries
 * `tenantClient.webhookEndpoint` directly — this module supplies the two
 * services every one of those call sites actually needs).
 */
@Module({
  imports: [OpenBaoModule],
  providers: [WebhookRegistryService, WebhookDeliveryService],
  exports: [WebhookRegistryService, WebhookDeliveryService],
})
export class WebhooksModule {}
