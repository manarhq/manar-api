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
import type { AppConfig } from '../config/env.validation';
import { redisClientOptions } from '../audit/live/redis.config';

const CHANNEL = 'manar:auth-cache-invalidate';

/**
 * Short-lived cache for the human auth guard (issuer to tenant, membership to roles), at most
 * `TTL_MS` old (founder decision 12). Security state is never served from it past a change:
 * every writer of a membership role or status, or of a tenant status, calls `invalidate()` AFTER
 * its transaction committed; that clears this replica at once and tells the other replicas over
 * Redis pub/sub. Only positive lookups are cached, so a new grant is visible immediately.
 * If Redis is down the other replicas fall back to the TTL (30 s) for that change.
 * A whole-cache clear is deliberate: those writes are rare, reads are every request.
 */
@Injectable()
export class AuthCache implements OnModuleInit, OnModuleDestroy {
  static readonly TTL_MS = 30_000;
  static readonly MAX_ENTRIES = 10_000;

  private readonly logger = new Logger(AuthCache.name);
  private readonly origin = randomUUID();
  private readonly entries = new Map<string, { at: number; value: unknown }>();
  /** Bumped on every clear: a load that started before it must not be stored. */
  private generation = 0;
  private publisher?: RedisClientType;
  private subscriber?: RedisClientType;

  constructor(
    @Optional() private readonly config?: ConfigService<AppConfig, true>,
  ) {}

  async onModuleInit(): Promise<void> {
    if (!this.config || process.env.AUTH_CACHE_PUBSUB === 'false') return;
    try {
      const options = redisClientOptions((k) =>
        this.config!.get(k, { infer: true }),
      );
      this.publisher = createClient(options);
      this.publisher.on('error', () => undefined);
      await this.publisher.connect();
      this.subscriber = this.publisher.duplicate();
      this.subscriber.on('error', () => undefined);
      await this.subscriber.connect();
      await this.subscriber.subscribe(CHANNEL, (origin: string) => {
        if (origin !== this.origin) this.clear();
      });
    } catch (error) {
      this.logger.warn(
        `Auth cache invalidation over Redis unavailable, other replicas rely on the ${AuthCache.TTL_MS / 1000} s TTL: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  async onModuleDestroy(): Promise<void> {
    await this.subscriber?.quit().catch(() => undefined);
    await this.publisher?.quit().catch(() => undefined);
  }

  /** Cached `load()` result for `key` (null results are never stored). */
  async remember<T>(
    key: string,
    load: () => Promise<T | null>,
  ): Promise<T | null> {
    const hit = this.entries.get(key);
    if (hit && Date.now() - hit.at < AuthCache.TTL_MS) return hit.value as T;
    const generation = this.generation;
    const value = await load();
    if (value !== null && generation === this.generation) {
      if (this.entries.size >= AuthCache.MAX_ENTRIES) this.entries.clear();
      this.entries.set(key, { at: Date.now(), value });
    }
    return value;
  }

  /** Call after the change committed. Clears this replica now; tells the others. */
  invalidate(): void {
    this.clear();
    void this.publisher
      ?.publish(CHANNEL, this.origin)
      .catch((e: unknown) =>
        this.logger.warn(`Auth cache invalidation not published: ${String(e)}`),
      );
  }

  private clear(): void {
    this.generation += 1;
    this.entries.clear();
  }
}
