import type { Logger } from '@nestjs/common';
import { createClient, type RedisClientType } from 'redis';
import type { redisClientOptions } from '../../audit/live/redis.config';

/**
 * One Redis connection on a request path, bounded: no offline queue (a
 * reconnecting client rejects at once), connect and every command limited
 * to REDIS_TIMEOUT_MS, a half-open client dropped so the next call starts a
 * fresh bounded attempt. A command that times out may still be applied by
 * Redis later; callers accept that (approximate counters, idempotency keys
 * that expire).
 */
export class BoundedRedis {
  private client: RedisClientType | undefined;

  constructor(
    private readonly options: ReturnType<typeof redisClientOptions>,
    private readonly timeoutMs: number,
    private readonly logger: Logger,
    private readonly label: string,
  ) {}

  async get(): Promise<RedisClientType> {
    if (this.client?.isReady) return this.client;
    if (this.client?.isOpen) {
      throw new Error(`${this.label}: Redis reconnecting`);
    }
    await this.connect();
    if (!this.client) {
      throw new Error(`${this.label}: no Redis connection available`);
    }
    return this.client;
  }

  async connect(): Promise<void> {
    const client: RedisClientType = createClient({
      ...this.options,
      disableOfflineQueue: true,
      socket: { ...this.options.socket, connectTimeout: this.timeoutMs },
      commandOptions: { timeout: this.timeoutMs },
    });
    client.on('error', (error: unknown) => {
      this.logger.warn(
        `${this.label} Redis connection error: ${message(error)}`,
      );
    });
    this.client = client;
    let timer: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        client.connect(),
        new Promise<never>((_, reject) => {
          timer = setTimeout(
            () =>
              reject(
                new Error(`Redis connect timed out after ${this.timeoutMs} ms`),
              ),
            this.timeoutMs,
          );
        }),
      ]);
    } catch (error) {
      this.client = undefined;
      client.destroy();
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  async close(): Promise<void> {
    try {
      // quit() waits for a reply a reconnecting client never gets.
      if (this.client?.isReady) await this.client.quit();
      else this.client?.destroy();
    } catch (error) {
      this.logger.warn(
        `Error closing ${this.label} Redis connection: ${message(error)}`,
      );
    }
  }
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
