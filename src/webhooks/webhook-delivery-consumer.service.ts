import { randomUUID } from 'node:crypto';
import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { KafkaJS } from '@confluentinc/kafka-javascript';
import type { AppConfig } from '../config/env.validation';
import { kafkaClientConfig } from '../audit/kafka.config';
import {
  AUDIT_EVENTS_TOPIC,
  DomainEventEnvelope,
} from '../audit/domain-event-envelope';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { TemporalClientService } from '../temporal/temporal-client.service';
import { WebhookDeliveryWorkflow } from '../temporal/workflows/webhook-delivery.workflow';

/**
 * Phase 12a (Webhooks, Section 51) — the Kafka-consuming half, mirroring
 * `AuditIndexerService`'s consumer pattern (`docs/audit-chain.md`) exactly:
 * same topic (`manar.audit-events`), same "fresh random consumer-group id
 * every process boot, `fromBeginning: false`" posture for the identical
 * "don't starve other concurrently-running test files / a fresh consumer
 * never needs to replay full history" reasons that service's own doc
 * comment gives.
 *
 * For every consumed event: resolves the tenant's own Prisma client (the
 * envelope carries `tenantId`), finds every `enabled` `WebhookEndpoint`
 * whose `subscribedEventTypes` includes this event's `eventType`, and for
 * each match creates a `WebhookDelivery` row (`status: PENDING`) and
 * starts a `WebhookDeliveryWorkflow` for it. The actual signed HTTP
 * delivery + Temporal retry happens entirely inside that workflow — this
 * service's only job is fan-out.
 *
 * **Idempotent under Kafka's at-least-once redelivery** the same way
 * `AuditIndexerService`'s upsert-by-`eventId` is: `WebhookDelivery` has a
 * `@@unique([webhookEndpointId, eventId])` constraint, so a redelivered
 * message that already produced a row for a given endpoint+event hits a
 * unique-constraint violation on `create` and is silently skipped —
 * exactly one `WebhookDelivery`/workflow per (endpoint, event) pair,
 * regardless of how many times Kafka redelivers the underlying message.
 */
@Injectable()
export class WebhookDeliveryConsumerService
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(WebhookDeliveryConsumerService.name);
  private readonly groupId = `manar-webhook-delivery-${randomUUID()}`;
  private readonly webhookTaskQueue: string;
  private consumer: KafkaJS.Consumer | undefined;

  constructor(
    private readonly configService: ConfigService<AppConfig, true>,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
    private readonly temporalClient: TemporalClientService,
  ) {
    // Its own dedicated queue, deliberately not `temporalClient.taskQueue`
    // -- see `WEBHOOK_DELIVERY_TASK_QUEUE`'s own doc comment
    // (`src/webhooks/webhooks.config.ts`) for why.
    this.webhookTaskQueue = this.configService.get(
      'WEBHOOK_DELIVERY_TASK_QUEUE',
      { infer: true },
    );
  }

  async onModuleInit(): Promise<void> {
    try {
      await this.start();
    } catch (error) {
      this.logger.warn(
        `Could not start the webhook delivery consumer's Kafka consumer at startup: ${errorMessage(error)}`,
      );
    }
  }

  async onModuleDestroy(): Promise<void> {
    try {
      await this.consumer?.disconnect();
    } catch (error) {
      this.logger.warn(
        `Error disconnecting webhook delivery consumer: ${errorMessage(error)}`,
      );
    }
  }

  private async start(): Promise<void> {
    const kafka = new KafkaJS.Kafka(
      kafkaClientConfig(
        (key) => this.configService.get(key, { infer: true }),
        `manar-webhook-delivery-${randomUUID()}`,
      ),
    );

    const admin = kafka.admin();
    try {
      await admin.connect();
      await admin.createTopics({
        topics: [
          { topic: AUDIT_EVENTS_TOPIC, numPartitions: 1, replicationFactor: 1 },
        ],
      });
    } finally {
      await admin.disconnect();
    }

    this.consumer = kafka.consumer({
      kafkaJS: { groupId: this.groupId, fromBeginning: false },
    });
    await this.consumer.connect();
    await this.consumer.subscribe({ topic: AUDIT_EVENTS_TOPIC });

    await this.consumer.run({
      eachMessage: async ({ message }) => {
        await this.handleMessage(message.value?.toString('utf8'));
      },
    });

    this.logger.log(
      `Webhook delivery consumer started (groupId="${this.groupId}", topic="${AUDIT_EVENTS_TOPIC}")`,
    );
  }

  private async handleMessage(raw: string | undefined): Promise<void> {
    if (!raw) return;
    let envelope: DomainEventEnvelope;
    try {
      envelope = JSON.parse(raw) as DomainEventEnvelope;
    } catch (error) {
      this.logger.warn(
        `Skipping unparseable audit-events message: ${errorMessage(error)}`,
      );
      return;
    }

    let tenantClient;
    try {
      tenantClient = await this.tenantDatabaseManager.getClient(
        envelope.tenantId,
      );
    } catch (error) {
      this.logger.warn(
        `Could not resolve tenant "${envelope.tenantId}" for webhook fan-out: ${errorMessage(error)}`,
      );
      return;
    }

    const endpoints = await tenantClient.webhookEndpoint.findMany({
      where: {
        enabled: true,
        subscribedEventTypes: { has: envelope.eventType },
      },
    });

    for (const endpoint of endpoints) {
      try {
        const delivery = await tenantClient.webhookDelivery.create({
          data: {
            webhookEndpointId: endpoint.id,
            eventId: envelope.eventId,
            eventType: envelope.eventType,
          },
        });

        await this.temporalClient.workflow.start(WebhookDeliveryWorkflow, {
          workflowId: `webhook-delivery-${delivery.id}`,
          taskQueue: this.webhookTaskQueue,
          args: [
            { tenantId: envelope.tenantId, webhookDeliveryId: delivery.id },
          ],
        });
      } catch (error) {
        if (isUniqueConstraintViolation(error)) {
          // A delivery row for this (endpoint, event) pair already exists
          // -- Kafka redelivered a message this consumer (or a prior
          // instance of it) already fanned out. Expected, not an error.
          continue;
        }
        this.logger.error(
          `Failed to fan out event "${envelope.eventId}" to webhook endpoint "${endpoint.id}": ${errorMessage(error)}`,
        );
      }
    }
  }
}

function isUniqueConstraintViolation(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === 'P2002'
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
