import { Injectable } from '@nestjs/common';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import { WebhookDeliveryService } from '../../webhooks/webhook-delivery.service';
import type {
  DeliverWebhookAttemptResult,
  WebhookDeliveryActivities,
  WebhookDeliveryActivityInput,
} from './webhook-delivery-activities.interface';

/**
 * The real implementation behind `WebhookDeliveryActivities` — mirrors
 * `AuditRetentionActivitiesFactory`'s shape exactly (a factory, not a class
 * Temporal's `Worker.create` invokes directly). Runs only inside the
 * separate worker process (`src/worker.main.ts`).
 */
@Injectable()
export class WebhookDeliveryActivitiesFactory {
  constructor(
    private readonly webhookDeliveryService: WebhookDeliveryService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

  build(): WebhookDeliveryActivities {
    return {
      deliverWebhookAttempt: async (
        input: WebhookDeliveryActivityInput,
      ): Promise<DeliverWebhookAttemptResult> => {
        const tenantClient = await this.tenantDatabaseManager.getClient(
          input.tenantId,
        );
        return this.webhookDeliveryService.attemptDelivery(
          tenantClient,
          input.webhookDeliveryId,
        );
      },
      markWebhookDeliveryFailed: async (
        input: WebhookDeliveryActivityInput,
      ): Promise<void> => {
        const tenantClient = await this.tenantDatabaseManager.getClient(
          input.tenantId,
        );
        await this.webhookDeliveryService.markFailed(
          tenantClient,
          input.webhookDeliveryId,
        );
      },
    };
  }
}
