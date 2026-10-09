import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createClient, type RedisClientType } from 'redis';
import { redisClientOptions } from '../audit/live/redis.config';
import type { AppConfig } from '../config/env.validation';

/** Placeholder value stored the instant a key is claimed, before the real response is known — distinguishes "a request with this key is genuinely still in flight" from "no request has ever used this key." */
const IN_PROGRESS_SENTINEL = '__manar_idempotency_in_progress__';

/**
 * Phase 12a (Section 8). Redis-backed claim/cache store behind
 * `IdempotencyInterceptor` — reuses this codebase's existing `redis`
 * client (the same library `RedisPubSubService`/`RedisThrottlerStorageService`
 * already use) rather than a new one.
 */
@Injectable()
export class IdempotencyStoreService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(IdempotencyStoreService.name);
  private readonly redisOptions: ReturnType<typeof redisClientOptions>;
  private client: RedisClientType | undefined;

  constructor(private readonly configService: ConfigService<AppConfig, true>) {
    this.redisOptions = redisClientOptions((key) =>
      this.configService.get(key, { infer: true }),
    );
  }

  async onModuleInit(): Promise<void> {
    try {
      await this.connect();
    } catch (error) {
      this.logger.warn(
        `Could not connect to Redis at startup (will retry lazily on first use): ${errorMessage(error)}`,
      );
    }
  }

  async onModuleDestroy(): Promise<void> {
    try {
      await this.client?.quit();
    } catch (error) {
      this.logger.warn(
        `Error closing Redis idempotency connection: ${errorMessage(error)}`,
      );
    }
  }

  /** Atomically claims `key` (`SET ... NX`) — `true` if this call is the first to see this key (the caller should proceed and eventually call `store`), `false` if someone already claimed it (the caller should check `getCached`). */
  async claim(key: string, ttlMs: number): Promise<boolean> {
    const client = await this.getClient();
    const result = await client.set(key, IN_PROGRESS_SENTINEL, {
      NX: true,
      PX: ttlMs,
    });
    return result === 'OK';
  }

  /** `undefined` if no real response has been stored yet for this key (still in flight, or never claimed) — a caller that got `claim() === false` and then sees `undefined` here should treat this as "duplicate request already in progress." */
  async getCached<T>(key: string): Promise<T | undefined> {
    const client = await this.getClient();
    const raw = await client.get(key);
    if (raw === null || raw === IN_PROGRESS_SENTINEL) return undefined;
    return JSON.parse(raw) as T;
  }

  /** Overwrites the in-progress sentinel with the real response, keeping the same TTL window (a replay later in the window returns this same value). */
  async store(key: string, value: unknown, ttlMs: number): Promise<void> {
    const client = await this.getClient();
    await client.set(key, JSON.stringify(value ?? null), { PX: ttlMs });
  }

  /** Releases a claim without ever storing a response — used when the original request *failed*, so a retry with the same key is free to attempt again rather than being permanently stuck replaying nothing. */
  async release(key: string): Promise<void> {
    const client = await this.getClient();
    await client.del(key);
  }

  private async getClient(): Promise<RedisClientType> {
    if (this.client?.isOpen) return this.client;
    await this.connect();
    if (!this.client) {
      throw new Error('Idempotency store: no Redis connection available');
    }
    return this.client;
  }

  private async connect(): Promise<void> {
    this.client = createClient(this.redisOptions);
    this.client.on('error', (error: unknown) => {
      this.logger.warn(
        `Redis idempotency connection error: ${errorMessage(error)}`,
      );
    });
    await this.client.connect();
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
