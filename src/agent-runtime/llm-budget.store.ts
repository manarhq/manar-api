import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createClient, type RedisClientType } from 'redis';
import type { AppConfig } from '../config/env.validation';

/** Keep a counter a day past the task's expiry, so a late call still sees it. */
const RETENTION_AFTER_EXPIRY_MS = 24 * 60 * 60 * 1000;

/**
 * Per-task LLM token usage in Redis (the limits store). Callers wrap every
 * call in `failClosed`, so a Redis failure denies the LLM call.
 *
 * ponytail: check-then-add, so concurrent calls on one task can overshoot the
 * budget by at most one call each; reserve-then-settle if that ever matters.
 */
@Injectable()
export class LlmBudgetStore implements OnModuleDestroy {
  private readonly logger = new Logger(LlmBudgetStore.name);
  private readonly url: string;
  private client: RedisClientType | undefined;

  constructor(configService: ConfigService<AppConfig, true>) {
    this.url = configService.get('REDIS_URL', { infer: true });
  }

  async onModuleDestroy(): Promise<void> {
    await this.client?.quit().catch(() => undefined);
  }

  private key(tenantId: string, taskId: string): string {
    return `manar:${tenantId}:llm-budget:${taskId}`;
  }

  async used(tenantId: string, taskId: string): Promise<number> {
    const raw = await (await this.getClient()).get(this.key(tenantId, taskId));
    return raw === null ? 0 : Number(raw);
  }

  async add(
    tenantId: string,
    taskId: string,
    tokens: number,
    taskExpiresAt: Date,
  ): Promise<number> {
    const client = await this.getClient();
    const key = this.key(tenantId, taskId);
    const total = await client.incrBy(key, tokens);
    await client.pExpireAt(
      key,
      taskExpiresAt.getTime() + RETENTION_AFTER_EXPIRY_MS,
    );
    return total;
  }

  private async getClient(): Promise<RedisClientType> {
    if (this.client?.isOpen) return this.client;
    // Fail fast rather than queue: a down Redis must deny now, not hang.
    this.client = createClient({
      url: this.url,
      disableOfflineQueue: true,
      socket: { connectTimeout: 2_000, reconnectStrategy: false },
    });
    this.client.on('error', (error: unknown) => {
      this.logger.warn(
        `Redis LLM budget connection error: ${error instanceof Error ? error.message : String(error)}`,
      );
    });
    await this.client.connect();
    return this.client;
  }
}
