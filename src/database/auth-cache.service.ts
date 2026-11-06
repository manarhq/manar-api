import {
  Injectable,
  Logger,
  Optional,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomUUID } from 'node:crypto';
import { createClient, type RedisClientType } from 'redis';
import { redisClientOptions } from '../audit/live/redis.config';
import type { AppConfig } from '../config/env.validation';

const CHANNEL = 'manar:auth-cache-invalidate';

/**
 * Short-lived cache for the human auth guard (issuer to tenant, membership to roles), at most
 * `TTL_MS` old (founder decision 12). Security state is never served from it past a change:
 * every writer of a membership role or status, or of a tenant status, calls `invalidate()` AFTER
 * its transaction committed; that clears this replica at once and tells the other replicas over
 * Redis pub/sub. Only positive lookups are cached, so a new grant is visible immediately.
 *
 * The cache is only used while this replica can hear those messages. Without a ready pub/sub
 * subscriber (Redis down, restarting, not yet connected) every lookup goes to the database, and the
 * whole cache is cleared each time the subscriber (re)connects, because invalidations sent during
 * the outage were missed. `AUTH_CACHE_PUBSUB=false` turns the cache off entirely. Connecting never
 * blocks start-up: the replica just runs without the cache until it is connected.
 * A whole-cache clear is deliberate: those writes are rare, reads are every request.
 */
@Injectable()
export class AuthCache implements OnModuleInit, OnModuleDestroy {
  static readonly TTL_MS = 30_000;
  static readonly MAX_ENTRIES = 10_000;
  /** A silent subscriber is detected within SOCKET_TIMEOUT_MS, far inside the 30 s TTL. */
  static readonly PING_INTERVAL_MS = 1_000;
  static readonly SOCKET_TIMEOUT_MS = 5_000;

  private readonly logger = new Logger(AuthCache.name);
  private readonly origin = randomUUID();
  private readonly entries = new Map<string, { at: number; value: unknown }>();
  /** Bumped on every clear: a load that started before it must not be stored. */
  private generation = 0;
  private publisher?: RedisClientType;
  private subscriber?: RedisClientType;
  private publisherConnecting?: Promise<unknown>;
  private connectTimeoutMs = 1000;
  /**
   * May entries be served? True in local mode (no Redis configured: tests and the CLI), otherwise
   * only while the subscriber is connected and subscribed.
   */
  private active: boolean;
  private readonly enabled: boolean;

  constructor(
    @Optional() private readonly config?: ConfigService<AppConfig, true>,
  ) {
    this.enabled = process.env.AUTH_CACHE_PUBSUB !== 'false';
    this.active = !config && this.enabled;
  }

  onModuleInit(): void {
    if (!this.config || !this.enabled) return;
    const timeout =
      this.config.get('REDIS_TIMEOUT_MS', { infer: true }) ?? 1000;
    const options = redisClientOptions(
      (k) => this.config!.get(k, { infer: true }),
      {
        connectTimeout: timeout,
        // A half-open connection (a network partition that sends no FIN) would otherwise look
        // healthy while invalidations are lost. The client pings every PING_INTERVAL_MS and the
        // socket is closed when nothing, not even a pong, arrives for SOCKET_TIMEOUT_MS; the
        // 'reconnecting' event below then bypasses and clears the cache.
        socketTimeout: AuthCache.SOCKET_TIMEOUT_MS,
        // Keep trying in the background; start-up never waits for it.
        reconnectStrategy: (retries: number) =>
          Math.min(2000, 100 * 2 ** Math.min(retries, 5)),
      },
    );
    this.publisher = createClient({
      ...options,
      pingInterval: AuthCache.PING_INTERVAL_MS,
    });
    this.publisher.on('error', () => undefined);
    this.publisherConnecting = this.publisher.connect().catch(() => undefined);

    const sub = this.publisher.duplicate() as RedisClientType;
    this.subscriber = sub;
    const down = (why: string) => {
      if (this.active) this.logger.warn(`Auth cache bypassed: ${why}`);
      this.active = false;
      this.clear();
    };
    sub.on('error', (e: unknown) =>
      down(
        `Redis subscriber error: ${e instanceof Error ? e.message : String(e)}`,
      ),
    );
    sub.on('end', () => down('Redis subscriber disconnected'));
    sub.on('reconnecting', () => down('Redis subscriber reconnecting'));
    sub.on('ready', () => {
      // Messages sent while we were away were missed: start from an empty cache, (re)subscribe
      // (idempotent for the same listener), clear again, and only then serve entries.
      this.active = false;
      this.clear();
      sub
        .subscribe(CHANNEL, this.onMessage)
        .then(() => {
          this.clear();
          this.active = true;
          this.logger.log('Auth cache active (pub/sub subscribed)');
        })
        .catch((e: unknown) => down(`subscribe failed: ${String(e)}`));
    });
    void sub.connect().catch(() => undefined);
  }

  private readonly onMessage = (origin: string): void => {
    if (origin !== this.origin) this.clear();
  };

  onModuleDestroy(): void {
    this.active = false;
    this.subscriber?.destroy();
    this.publisher?.destroy();
  }

  /** Cached `load()` result for `key` (null results are never stored). */
  async remember<T>(
    key: string,
    load: () => Promise<T | null>,
  ): Promise<T | null> {
    if (!this.enabled || !this.active) return load();
    const hit = this.entries.get(key);
    if (hit && Date.now() - hit.at < AuthCache.TTL_MS) return hit.value as T;
    const generation = this.generation;
    // The TTL runs from when the load started: the value is at most that old when it is stored.
    const startedAt = Date.now();
    const value = await load();
    if (value !== null && generation === this.generation && this.active) {
      if (this.entries.size >= AuthCache.MAX_ENTRIES) this.entries.clear();
      this.entries.set(key, { at: startedAt, value });
    }
    return value;
  }

  /**
   * Call after the change committed. Clears this replica now and tells the others; resolves when
   * the message was handed to Redis (a CLI waits for it, the API ignores the promise).
   */
  async invalidate(): Promise<void> {
    this.clear();
    const publisher = this.publisher;
    if (!publisher) return;
    if (!publisher.isReady && this.publisherConnecting) {
      // Just started (a CLI): give the connection a moment instead of dropping the message.
      await Promise.race([
        this.publisherConnecting,
        new Promise((r) => setTimeout(r, this.connectTimeoutMs)),
      ]);
    }
    if (!publisher.isReady) {
      this.logger.warn(
        'Auth cache invalidation not published (Redis publisher not ready); other replicas rely on their own bypass',
      );
      return;
    }
    await publisher.publish(CHANNEL, this.origin).catch((e: unknown) => {
      this.logger.warn(`Auth cache invalidation not published: ${String(e)}`);
    });
  }

  private clear(): void {
    this.generation += 1;
    this.entries.clear();
  }
}
