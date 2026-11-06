import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createClient, type RedisClientType } from 'redis';
import { redisClientOptions } from './redis.config';
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
 * "publisher" connection is kept here (`onModuleInit`) and subscribers use a
 * `duplicate()`d connection (`subscribeTenant`, one per tenant per process,
 * shared by that tenant's open streams) — never the publisher itself.
 */
@Injectable()
export class RedisPubSubService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RedisPubSubService.name);
  private readonly redisOptions: ReturnType<typeof redisClientOptions>;
  private publisher: RedisClientType | undefined;
  private readonly shared = new Map<string, SharedSubscriber>();

  constructor(private readonly configService: ConfigService<AppConfig, true>) {
    this.redisOptions = redisClientOptions((key) =>
      this.configService.get(key, { infer: true }),
    );
  }

  /**
   * Best-effort connect at boot — never lets a Redis outage fail the whole
   * Nest application's startup, the same posture
   * `KafkaPublisherService.onModuleInit` already establishes for Kafka.
   */
  async onModuleInit(): Promise<void> {
    try {
      this.publisher = createClient(this.redisOptions);
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
    for (const entry of this.shared.values()) {
      try {
        (await entry.ready).destroy();
      } catch {
        // never opened
      }
    }
    this.shared.clear();
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
        this.publisher = createClient(this.redisOptions);
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
   * Subscribes to one tenant's live channel. All `GET /events/live` connections of one tenant in
   * this process share ONE dedicated Redis subscriber (a `duplicate()`d connection, never the
   * publisher), ref-counted: it is opened by the first listener and unsubscribed and closed when
   * the last one leaves. The cost is one Redis connection per active tenant per process, not one
   * per open console tab. A tenant's listeners only ever see that tenant's channel.
   *
   * Rejects when the subscriber cannot be opened within `SUBSCRIBE_TIMEOUT_MS`; the caller must
   * answer 503 and not start a stream. `onMessage` receives the already-parsed envelope; a
   * listener that throws does not stop the others. Call the returned `unsubscribe` once, when
   * the connection closes (further calls do nothing).
   */
  async subscribeTenant(
    tenantId: string,
    onMessage: (envelope: DomainEventEnvelope) => void,
  ): Promise<LiveSubscription> {
    let entry = this.shared.get(tenantId);
    if (!entry) {
      entry = this.openShared(tenantId);
      this.shared.set(tenantId, entry);
    }
    const joined = entry;
    joined.listeners.add(onMessage);
    try {
      await joined.ready;
    } catch (error) {
      // The open failed and cleaned itself up: forget it so the next caller tries afresh.
      joined.listeners.delete(onMessage);
      if (this.shared.get(tenantId) === joined) this.shared.delete(tenantId);
      throw error;
    }
    let left = false;
    return {
      unsubscribe: async () => {
        if (left) return;
        left = true;
        await this.leave(tenantId, joined, onMessage);
      },
    };
  }

  /** Number of tenants with an open shared subscriber (tests and diagnostics). */
  sharedSubscriberCount(): number {
    return this.shared.size;
  }

  private openShared(tenantId: string): SharedSubscriber {
    const listeners = new Set<(envelope: DomainEventEnvelope) => void>();
    const channel = tenantLiveChannel(tenantId);
    const ready = (async () => {
      const base = this.publisher ?? createClient(this.redisOptions);
      const subscriber = base.duplicate() as RedisClientType;
      subscriber.on('error', (error: unknown) => {
        this.logger.warn(
          `Redis subscriber connection error (tenant "${tenantId}"): ${errorMessage(error)}`,
        );
      });
      try {
        await withTimeout(async () => {
          await subscriber.connect();
          await subscriber.subscribe(channel, (message: string) => {
            let envelope: DomainEventEnvelope;
            try {
              envelope = JSON.parse(message) as DomainEventEnvelope;
            } catch (error) {
              this.logger.warn(
                `Failed to parse a live-feed message on channel "${channel}": ${errorMessage(error)}`,
              );
              return;
            }
            for (const listener of [...listeners]) {
              try {
                listener(envelope);
              } catch (error) {
                this.logger.warn(
                  `A live-feed listener failed (tenant "${tenantId}"): ${errorMessage(error)}`,
                );
              }
            }
          });
        }, SUBSCRIBE_TIMEOUT_MS);
      } catch (error) {
        subscriber.destroy();
        throw error;
      }
      return subscriber;
    })();
    // A failed open is reported to every waiter below; this keeps the rejection from being unhandled.
    ready.catch(() => undefined);
    return { listeners, ready };
  }

  private async leave(
    tenantId: string,
    entry: SharedSubscriber,
    onMessage: (envelope: DomainEventEnvelope) => void,
  ): Promise<void> {
    entry.listeners.delete(onMessage);
    if (entry.listeners.size > 0) return;
    if (this.shared.get(tenantId) === entry) this.shared.delete(tenantId);
    try {
      const subscriber = await entry.ready;
      try {
        await subscriber.unsubscribe(tenantLiveChannel(tenantId));
      } finally {
        await subscriber.quit();
      }
    } catch (error) {
      // An open that failed already cleaned itself up; anything else is only worth a warning.
      this.logger.warn(
        `Error closing the live-feed subscriber for tenant "${tenantId}": ${errorMessage(error)}`,
      );
    }
  }
}

/** Bound on opening a shared subscriber, so a Redis outage answers 503 instead of hanging. */
export const SUBSCRIBE_TIMEOUT_MS = 3_000;

interface SharedSubscriber {
  listeners: Set<(envelope: DomainEventEnvelope) => void>;
  ready: Promise<RedisClientType>;
}

async function withTimeout(
  work: () => Promise<void>,
  ms: number,
): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      work(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error('Redis subscribe timed out')),
          ms,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
