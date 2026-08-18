import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
// `@confluentinc/kafka-javascript`'s `KafkaJS` compatibility surface — see
// docs/audit-chain.md for why this library was chosen over `kafkajs`
// (unmaintained since 2023) or bare `node-rdkafka`.
import { KafkaJS } from '@confluentinc/kafka-javascript';
import type { AppConfig } from '../config/env.validation';
import {
  AUDIT_EVENTS_TOPIC,
  DomainEventEnvelope,
} from './domain-event-envelope';

const CONNECT_RETRY_ATTEMPTS = 3;
const CONNECT_RETRY_DELAY_MS = 200;

/**
 * Thin wrapper around a single Kafka producer connection (Section 29 — the
 * Kafka backbone is a downstream notification channel, never the source of
 * truth: `AuditService.record` already committed the `AuditEvent` to
 * Postgres, the tenant database's own transaction, before this class is
 * ever called). Deliberately minimal — no consumer logic here at all (Phase
 * 9b's own indexer owns that); this phase's own Kafka *consumer* code
 * exists only inside `test/audit-kafka-idempotency.e2e-spec.ts`, proving the
 * envelope/idempotency contract without shipping unused production
 * consumer plumbing ahead of the phase that actually needs one.
 */
@Injectable()
export class KafkaPublisherService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(KafkaPublisherService.name);
  private readonly topic: string;
  private producer: KafkaJS.Producer | undefined;
  private connecting: Promise<void> | undefined;

  constructor(private readonly configService: ConfigService<AppConfig, true>) {
    this.topic = this.configService.get('KAFKA_AUDIT_TOPIC', { infer: true });
  }

  async onModuleInit(): Promise<void> {
    await this.ensureConnected();
  }

  async onModuleDestroy(): Promise<void> {
    if (!this.producer) return;
    try {
      await this.producer.disconnect();
    } catch (error) {
      this.logger.warn(
        `Error disconnecting Kafka producer during shutdown: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  /**
   * Publishes one envelope to `AUDIT_EVENTS_TOPIC`. Never throws — a Kafka
   * outage must never block or roll back the caller's already-committed
   * `AuditEvent` write (see `AuditService.record`'s doc comment: the
   * Postgres write is authoritative, Kafka is a downstream notification).
   * Retries a bounded number of times with a short fixed delay (the same
   * "keep it simple" retry shape `HttpToolAdapter` already uses for its own
   * outbound calls — Section 35's precedent), then logs loudly and gives up
   * rather than retrying forever.
   *
   * Keyed by `tenantId` (not `eventId`) so Kafka's own partition-ordering
   * guarantee (messages with the same key land on the same partition, in
   * publish order) gives every consumer a per-tenant ordered stream —
   * useful for a future indexer that wants to process one tenant's events
   * in the order they actually happened, without needing every event ever
   * produced to land on a single partition.
   */
  async publish(envelope: DomainEventEnvelope): Promise<void> {
    for (let attempt = 1; attempt <= CONNECT_RETRY_ATTEMPTS; attempt += 1) {
      try {
        await this.ensureConnected();
        await this.producer?.send({
          topic: this.topic,
          messages: [
            {
              key: envelope.tenantId,
              value: JSON.stringify(envelope),
            },
          ],
        });
        return;
      } catch (error) {
        const isLastAttempt = attempt === CONNECT_RETRY_ATTEMPTS;
        this.logger.warn(
          `Failed to publish audit event "${envelope.eventId}" (eventType="${envelope.eventType}") to Kafka topic "${this.topic}" (attempt ${attempt}/${CONNECT_RETRY_ATTEMPTS}): ${error instanceof Error ? error.message : String(error)}`,
        );
        if (isLastAttempt) {
          this.logger.error(
            `Giving up publishing audit event "${envelope.eventId}" to Kafka after ${CONNECT_RETRY_ATTEMPTS} attempts — the AuditEvent row itself is already committed to Postgres and remains the authoritative record; this event will not appear on the Kafka topic.`,
          );
          return;
        }
        await delay(CONNECT_RETRY_DELAY_MS);
      }
    }
  }

  private async ensureConnected(): Promise<void> {
    if (this.producer) return;
    if (this.connecting) return this.connecting;

    this.connecting = (async () => {
      const brokers = this.configService
        .get('KAFKA_BROKERS', { infer: true })
        .split(',')
        .map((broker) => broker.trim())
        .filter(Boolean);
      const clientId = this.configService.get('KAFKA_CLIENT_ID', {
        infer: true,
      });

      const kafka = new KafkaJS.Kafka({
        kafkaJS: { brokers, clientId },
      });
      const producer = kafka.producer({
        kafkaJS: { allowAutoTopicCreation: true },
      });
      await producer.connect();
      await this.ensureTopicExists(kafka);
      this.producer = producer;
    })();

    try {
      await this.connecting;
    } finally {
      this.connecting = undefined;
    }
  }

  /**
   * Idempotent, no separate init job (the same "resolve-or-create
   * automatically, every boot" posture `OpenFgaClientService.onModuleInit`
   * already establishes for the OpenFGA store/model — see
   * docs/authorization-model.md — rather than Phase 5's `openfga-db-init`
   * one-shot-job pattern, since there's no destructive-if-rerun hazard
   * here). `createTopics` on an already-existing topic is a documented
   * no-op (returns `false`, doesn't throw), so this is safe to call on
   * every process boot.
   */
  private async ensureTopicExists(kafka: KafkaJS.Kafka): Promise<void> {
    const admin = kafka.admin();
    try {
      await admin.connect();
      await admin.createTopics({
        topics: [{ topic: this.topic, numPartitions: 1, replicationFactor: 1 }],
      });
    } catch (error) {
      this.logger.warn(
        `Could not confirm Kafka topic "${this.topic}" exists (it may already exist, or auto-creation may be disabled broker-side): ${error instanceof Error ? error.message : String(error)}`,
      );
    } finally {
      await admin.disconnect();
    }
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Re-exported so callers only ever need this module's own export surface.
export { AUDIT_EVENTS_TOPIC };
