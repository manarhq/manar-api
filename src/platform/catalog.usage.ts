import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createClient, type RedisClientType } from 'redis';
import { redisClientOptions } from '../audit/live/redis.config';
import type { AppConfig } from '../config/env.validation';

/** Keep a month's counter long enough for the fleet to read last month's total. */
const RETENTION_SECONDS = 400 * 24 * 60 * 60;

/** `2026-10` in UTC. */
export function usageMonth(at: Date = new Date()): string {
  return at.toISOString().slice(0, 7);
}

/**
 * Model tokens per tenant per calendar month (UTC), across the LLM proxy and the assistant, in
 * Redis (the limits store). Callers wrap reads that gate a call in `failClosed`.
 *
 * ponytail: check-then-add like `LlmBudgetStore`, so concurrent calls can overshoot a quota by at
 * most one call each.
 */
@Injectable()
export class CatalogUsageStore implements OnModuleDestroy {
  private readonly logger = new Logger(CatalogUsageStore.name);
  private readonly redisOptions: ReturnType<typeof redisClientOptions>;
  private client: RedisClientType | undefined;

  constructor(config: ConfigService<AppConfig, true>) {
    this.redisOptions = redisClientOptions((key) =>
      config.get(key, { infer: true }),
    );
  }

  async onModuleDestroy(): Promise<void> {
    await this.client?.quit().catch(() => undefined);
  }

  private key(tenantId: string, month: string): string {
    return `manar:${tenantId}:llm-tokens:${month}`;
  }

  async used(tenantId: string, month = usageMonth()): Promise<number> {
    const raw = await (await this.getClient()).get(this.key(tenantId, month));
    return raw === null ? 0 : Number(raw);
  }

  async add(tenantId: string, tokens: number): Promise<number> {
    const client = await this.getClient();
    const key = this.key(tenantId, usageMonth());
    const total = await client.incrBy(key, Math.max(0, Math.round(tokens)));
    await client.expire(key, RETENTION_SECONDS);
    return total;
  }

  private async getClient(): Promise<RedisClientType> {
    if (this.client?.isOpen) return this.client;
    // Fail fast rather than queue: a down Redis must deny now, not hang.
    this.client = createClient({
      ...this.redisOptions,
      disableOfflineQueue: true,
      socket: {
        ...this.redisOptions.socket,
        connectTimeout: 2_000,
        reconnectStrategy: false,
      },
    });
    this.client.on('error', (error: unknown) => {
      this.logger.warn(
        `Redis usage connection error: ${error instanceof Error ? error.message : String(error)}`,
      );
    });
    await this.client.connect();
    return this.client;
  }
}
