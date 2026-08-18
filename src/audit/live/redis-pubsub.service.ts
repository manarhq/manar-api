import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createClient, type RedisClientType } from 'redis';
import type { AppConfig } from '../../config/env.validation';
import type { DomainEventEnvelope } from '../domain-event-envelope';

/** `manar:audit-live:<tenantId>` — one Redis pub/sub channel per tenant. */
export function tenantLiveChannel(tenantId: string): string {
  return `manar:audit-live:${tenantId}`;
}

export interface LiveSubscription {
  unsubscribe: () => Promise<void>;
}

/**
 * Phase 9b (Live SSE, Section 62). Redis's approved use here is SSE fanout
 * — a pub/sub channel per tenant that any API replica can subscribe to, so
 * a live event reaches every connected dashboard client regardless of
 * which replica received the original write (`docs/audit-chain.md`).
 * `AuditIndexerService` (the same Kafka consumer that indexes into
 * OpenSearch) publishes every consumed envelope here; `LiveEventsController`
 * subscribes per open `GET /events/live` connection.
 *
 * Two separate Redis client connections, per `node-redis`'s own documented
 * pub/sub contract: RESP2 pub/sub takes over a connection entirely once
 * `SUBSCRIBE` is issued (no other commands can share it), so a dedicated
 * "publisher" connection is kept here (`onModuleInit`) and every *subscriber*
 * gets its own fresh `duplicate()`d connection (`subscribeTenant`) — never
 * the shared publisher connection itself.
 */
@Injectable()
export class RedisPubSubService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RedisPubSubService.name);
  private readonly url: string;
  private publisher: RedisClientType | undefined;

  constructor(private readonly configService: ConfigService<AppConfig, true>) {
    this.url = this.configService.get('REDIS_URL', { infer: true });
  }

  /**
   * Best-effort connect at boot — never lets a Redis outage fail the whole
   * Nest application's startup, the same posture
   * `KafkaPublisherService.onModuleInit` already establishes for Kafka.
   */
  async onModuleInit(): Promise<void> {
    try {
      this.publisher = createClient({ url: this.url });
      this.publisher.on('error', (error: unknown) => {
        this.logger.warn(
          `Redis publisher connection error: ${errorMessage(error)}`,
        );
      });
      await this.publisher.connect();
    } catch (error) {
      this.logger.warn(
        `Could not connect to Redis at startup (will retry lazily on first publish): ${errorMessage(error)}`,
      );
      this.publisher = undefined;
    }
  }

  async onModuleDestroy(): Promise<void> {
    try {
      await this.publisher?.quit();
    } catch (error) {
      this.logger.warn(`Error closing Redis publisher: ${errorMessage(error)}`);
    }
  }

  /**
   * Publishes one envelope to its tenant's live channel. Never throws —
   * the live feed is a best-effort convenience surface, never something a
   * caller's own success depends on (the same posture
   * `KafkaPublisherService.publish` already takes for Kafka itself).
   */
  async publish(envelope: DomainEventEnvelope): Promise<void> {
    try {
      if (!this.publisher) {
        this.publisher = createClient({ url: this.url });
        this.publisher.on('error', (error: unknown) => {
          this.logger.warn(
            `Redis publisher connection error: ${errorMessage(error)}`,
          );
        });
        await this.publisher.connect();
      }
      await this.publisher.publish(
        tenantLiveChannel(envelope.tenantId),
        JSON.stringify(envelope),
      );
    } catch (error) {
      this.logger.warn(
        `Failed to publish audit event "${envelope.eventId}" to the live feed for tenant "${envelope.tenantId}": ${errorMessage(error)}`,
      );
    }
  }

  /**
   * Subscribes to one tenant's live channel for the duration of a single
   * `GET /events/live` connection — a fresh, dedicated `duplicate()`d
   * connection per call (see class doc comment). `onMessage` is invoked
   * with each envelope's already-`JSON.parse`d payload. Returns an
   * `unsubscribe` the caller must call exactly once (on connection close)
   * to disconnect this dedicated connection — never left open past the
   * SSE connection's own lifetime.
   */
  async subscribeTenant(
    tenantId: string,
    onMessage: (envelope: DomainEventEnvelope) => void,
  ): Promise<LiveSubscription> {
    const base = this.publisher ?? createClient({ url: this.url });
    const subscriber = base.duplicate() as RedisClientType;
    subscriber.on('error', (error: unknown) => {
      this.logger.warn(
        `Redis subscriber connection error (tenant "${tenantId}"): ${errorMessage(error)}`,
      );
    });
    await subscriber.connect();

    const channel = tenantLiveChannel(tenantId);
    await subscriber.subscribe(channel, (message: string) => {
      try {
        onMessage(JSON.parse(message) as DomainEventEnvelope);
      } catch (error) {
        this.logger.warn(
          `Failed to parse a live-feed message on channel "${channel}": ${errorMessage(error)}`,
        );
      }
    });

    return {
      unsubscribe: async () => {
        try {
          await subscriber.unsubscribe(channel);
        } finally {
          await subscriber.quit();
        }
      },
    };
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
