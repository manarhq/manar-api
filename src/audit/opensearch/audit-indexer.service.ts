import { randomUUID } from 'node:crypto';
import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { KafkaJS } from '@confluentinc/kafka-javascript';
import type { AppConfig } from '../../config/env.validation';
import {
  AUDIT_EVENTS_TOPIC,
  DomainEventEnvelope,
} from '../domain-event-envelope';
import { OpenSearchIndexService } from './opensearch-client.service';
import { extractAuditSearchFields } from './audit-search-fields';
import { RedisPubSubService } from '../live/redis-pubsub.service';

/**
 * Phase 9b: the real Kafka consumer behind Section 45's "upsert by
 * `eventId`, never blindly append" requirement, and Section 62's live SSE
 * feed. Subscribes to Phase 9a's `manar.audit-events` topic
 * (`docs/audit-chain.md`) and, for every message: upserts it into
 * OpenSearch (`OpenSearchIndexService.upsertAuditEvent`) and publishes it
 * to its tenant's Redis live channel (`RedisPubSubService.publish`) — one
 * consumer doing both, since both are naturally derived from the exact
 * same Kafka stream and both need the exact same idempotent-per-message
 * handling; splitting them into two independent consumer groups would
 * mean twice the broker connections/rebalancing for no benefit (OpenSearch
 * indexing is already idempotent by construction, and a duplicate Redis
 * publish for the live feed is harmless — SSE is a best-effort stream, not
 * the source of truth).
 *
 * **Consumer group id**: a fresh random id every process start
 * (`manar-audit-indexer-<uuid>`), not a fixed name. A fixed shared group id
 * would mean every test file that boots `AppModule` (this service lives in
 * its module graph) joins the *same* consumer group against a
 * single-partition topic, where only one member ever receives traffic at a
 * time, starving every other concurrently-running test file's own indexer
 * instance.
 *
 * **`fromBeginning: false`** (a fresh group starts from the topic's
 * *current* end, not its start): full historical backfill is deliberately
 * `pnpm manar audit:reindex`'s job (`AuditReindexService`, reading
 * straight from Postgres — see that service's own doc comment), never this
 * live consumer's — a from-scratch reconstruction must not depend on how
 * much history Kafka happens to still be retaining, and a fresh random
 * group replaying an ever-growing topic from its start on every single
 * process boot would make this consumer's own catch-up time grow
 * unboundedly with the topic's total lifetime history, for no correctness
 * benefit (OpenSearch indexing is already idempotent by construction either
 * way; a message published before this particular process started simply
 * isn't this instance's job to backfill).
 */
@Injectable()
export class AuditIndexerService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(AuditIndexerService.name);
  private readonly groupId = `manar-audit-indexer-${randomUUID()}`;
  private consumer: KafkaJS.Consumer | undefined;

  constructor(
    private readonly configService: ConfigService<AppConfig, true>,
    private readonly openSearchIndexService: OpenSearchIndexService,
    private readonly redisPubSubService: RedisPubSubService,
  ) {}

  /**
   * Best-effort start — never lets a Kafka outage fail the whole Nest
   * application's startup, the same posture every other Kafka/OpenSearch/
   * Redis client in this phase already establishes.
   */
  async onModuleInit(): Promise<void> {
    try {
      await this.start();
    } catch (error) {
      this.logger.warn(
        `Could not start the audit indexer's Kafka consumer at startup: ${errorMessage(error)}`,
      );
    }
  }

  async onModuleDestroy(): Promise<void> {
    try {
      await this.consumer?.disconnect();
    } catch (error) {
      this.logger.warn(
        `Error disconnecting audit indexer consumer: ${errorMessage(error)}`,
      );
    }
  }

  private async start(): Promise<void> {
    const brokers = this.configService
      .get('KAFKA_BROKERS', { infer: true })
      .split(',')
      .map((broker) => broker.trim())
      .filter(Boolean);

    const kafka = new KafkaJS.Kafka({
      kafkaJS: { brokers, clientId: `manar-audit-indexer-${randomUUID()}` },
    });

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
      `Audit indexer consumer started (groupId="${this.groupId}", topic="${AUDIT_EVENTS_TOPIC}")`,
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

    try {
      // Phase 11b Part 1 (Section 66's GET /audit filters) — real, indexed
      // search fields derived from this same envelope's actor/data, added
      // alongside the unindexed actor/data blobs (never replacing them —
      // see extractAuditSearchFields's own doc comment).
      const searchFields = extractAuditSearchFields(
        envelope.eventType,
        envelope.actor,
        envelope.data,
      );
      await this.openSearchIndexService.upsertAuditEvent({
        eventId: envelope.eventId,
        tenantId: envelope.tenantId,
        // `sequence` defaults to 0 only for a hand-crafted envelope that
        // omits it (e.g. Phase 9a's own idempotency test fixture, which
        // never reaches this consumer in practice) — every envelope this
        // codebase's own `AuditService.record` actually publishes sets it
        // (see `domain-event-envelope.ts`'s doc comment); `audit:reindex`
        // (reading straight from Postgres) is the authoritative source for
        // this value regardless.
        sequence: envelope.sequence ?? 0,
        eventType: envelope.eventType,
        correlationId: envelope.correlationId,
        actor: envelope.actor,
        timestamp: envelope.timestamp,
        data: envelope.data,
        previousHash: envelope.previousHash ?? null,
        eventHash: envelope.eventHash ?? envelope.eventId,
        ...searchFields,
      });
    } catch (error) {
      this.logger.error(
        `Failed to index audit event "${envelope.eventId}" into OpenSearch: ${errorMessage(error)}`,
      );
    }

    await this.redisPubSubService.publish(envelope);
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
