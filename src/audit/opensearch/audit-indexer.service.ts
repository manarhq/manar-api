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
import { kafkaClientConfig } from '../kafka.config';
import {
  AUDIT_EVENTS_TOPIC,
  DomainEventEnvelope,
} from '../domain-event-envelope';
import {
  AuditEventDocument,
  OpenSearchIndexService,
} from './opensearch-client.service';
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
  /** Largest Bulk request, and the longest a partial batch waits at the broker. */
  static readonly BATCH_MAX = 200;
  static readonly FLUSH_MS = 250;

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
    const kafka = new KafkaJS.Kafka(
      kafkaClientConfig(
        (key) => this.configService.get(key, { infer: true }),
        `manar-audit-indexer-${randomUUID()}`,
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
      kafkaJS: {
        groupId: this.groupId,
        fromBeginning: false,
        maxWaitTimeInMs: AuditIndexerService.FLUSH_MS,
      },
      'js.consumer.max.batch.size': AuditIndexerService.BATCH_MAX,
    });
    await this.consumer.connect();
    await this.consumer.subscribe({ topic: AUDIT_EVENTS_TOPIC });

    // One Bulk request per fetched batch instead of a refreshed index call per event. A batch
    // never exceeds BATCH_MAX messages and a partial batch is delivered after FLUSH_MS.
    // Offsets are resolved only after the batch was handed to OpenSearch, so a crash mid-batch
    // redelivers it (at-least-once; indexing is idempotent by eventId).
    await this.consumer.run({
      eachBatchAutoResolve: false,
      eachBatch: async (payload) => {
        const { messages } = payload.batch;
        await this.handleBatch(messages.map((m) => m.value?.toString('utf8')));
        const last = messages[messages.length - 1];
        if (last) payload.resolveOffset(last.offset);
        await payload.heartbeat();
      },
    });

    this.logger.log(
      `Audit indexer consumer started (groupId="${this.groupId}", topic="${AUDIT_EVENTS_TOPIC}")`,
    );
  }

  /** Bulk-indexes a batch, then publishes each event to the live feed. Never throws on index errors. */
  async handleBatch(raws: (string | undefined)[]): Promise<void> {
    const envelopes: DomainEventEnvelope[] = [];
    for (const raw of raws) {
      if (!raw) continue;
      try {
        envelopes.push(JSON.parse(raw) as DomainEventEnvelope);
      } catch (error) {
        this.logger.warn(
          `Skipping unparseable audit-events message: ${errorMessage(error)}`,
        );
      }
    }
    if (envelopes.length === 0) return;

    const documents = envelopes.map(toDocument);
    try {
      await this.openSearchIndexService.bulkUpsertAuditEvents(documents, {
        refresh: false,
      });
    } catch (bulkError) {
      // One bad document must not hold back the rest: retry them one by one and log the
      // failures (audit:reindex heals any that stay missing, as before batching).
      this.logger.warn(
        `Bulk index of ${documents.length} audit event(s) failed (${errorMessage(bulkError)}); retrying one by one`,
      );
      for (const document of documents) {
        try {
          await this.openSearchIndexService.upsertAuditEvent(document);
        } catch (error) {
          this.logger.error(
            `Failed to index audit event "${document.eventId}" into OpenSearch: ${errorMessage(error)}`,
          );
        }
      }
    }

    for (const envelope of envelopes) {
      await this.redisPubSubService.publish(envelope);
    }
  }
}

/**
 * Phase 11b Part 1 (Section 66's GET /audit filters): real, indexed search fields derived from
 * the envelope's actor/data, added alongside the unindexed actor/data blobs. `sequence` defaults
 * to 0 only for a hand-crafted envelope that omits it; `audit:reindex` is authoritative.
 */
function toDocument(envelope: DomainEventEnvelope): AuditEventDocument {
  return {
    eventId: envelope.eventId,
    tenantId: envelope.tenantId,
    sequence: envelope.sequence ?? 0,
    eventType: envelope.eventType,
    correlationId: envelope.correlationId,
    actor: envelope.actor,
    timestamp: envelope.timestamp,
    data: envelope.data,
    previousHash: envelope.previousHash ?? null,
    eventHash: envelope.eventHash ?? envelope.eventId,
    ...extractAuditSearchFields(
      envelope.eventType,
      envelope.actor,
      envelope.data,
    ),
  };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
