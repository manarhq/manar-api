import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { redisClientOptions } from '../audit/live/redis.config';
import { BoundedRedis } from '../common/redis/bounded-redis';

const PLATFORM_KEY = 'manar:ks-epoch:platform';
const tenantKey = (tenantId: string) => `manar:ks-epoch:tenant:${tenantId}`;

/**
 * Spec §7.2: the epoch is the correctness check for the in-memory kill-switch
 * cache. Two counters in Valkey (platform, and one per tenant), bumped by every
 * writer of a stop condition after its commit. `read` returns both in one
 * round trip; a cached entry is only trusted while the value is unchanged and
 * younger than `maxAgeMs` (the staleness bound if a bump is lost: writer died
 * between commit and bump, or Valkey was flushed).
 *
 * `read` throws when Valkey is unavailable: the caller must then read
 * PostgreSQL and cache nothing. `bump*` never throw (the change is already
 * committed; other replicas catch up within `maxAgeMs`).
 */
@Injectable()
export class KillSwitchEpochService implements OnModuleDestroy {
  private readonly logger = new Logger(KillSwitchEpochService.name);
  private readonly redis: BoundedRedis;
  readonly maxAgeMs: number;

  constructor(config: ConfigService<AppConfig, true>) {
    this.redis = new BoundedRedis(
      redisClientOptions((key) => config.get(key, { infer: true })),
      config.get('REDIS_TIMEOUT_MS', { infer: true }),
      this.logger,
      'Kill-switch epoch',
    );
    this.maxAgeMs =
      config.get('KILL_SWITCH_CACHE_MAX_AGE_MS', { infer: true }) ?? 2000;
  }

  async onModuleDestroy(): Promise<void> {
    await this.redis.close();
  }

  async read(tenantId: string): Promise<string> {
    const client = await this.redis.get();
    const [platform, tenant] = await client.mGet([
      PLATFORM_KEY,
      tenantKey(tenantId),
    ]);
    return `${platform ?? '0'}:${tenant ?? '0'}`;
  }

  bumpTenant(tenantId: string): Promise<void> {
    return this.bump(tenantKey(tenantId));
  }

  bumpPlatform(): Promise<void> {
    return this.bump(PLATFORM_KEY);
  }

  private async bump(key: string): Promise<void> {
    try {
      await (await this.redis.get()).incr(key);
    } catch (error) {
      this.logger.warn(
        `Kill-switch epoch bump failed; other replicas catch up within ${this.maxAgeMs} ms: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
}
