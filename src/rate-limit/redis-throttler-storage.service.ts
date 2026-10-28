import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { ThrottlerStorage } from '@nestjs/throttler';
import type { AppConfig } from '../config/env.validation';
import { redisClientOptions } from '../audit/live/redis.config';
import { BoundedRedis } from '../common/redis/bounded-redis';

/**
 * Mirrors `@nestjs/throttler`'s own `ThrottlerStorageRecord` shape exactly
 * (defined locally rather than imported — that interface lives in an
 * internal module the package's public entry point doesn't re-export).
 */
interface ThrottlerStorageRecord {
  totalHits: number;
  timeToExpire: number;
  isBlocked: boolean;
  timeToBlockExpire: number;
}

/**
 * Spec 7.3: GCRA (generic cell rate algorithm), one atomic script per check. The throttler's
 * `ttl` and `limit` map to an emission interval of `ttl / limit` and a burst of `limit`, so
 * "N requests per window" keeps its meaning while the window no longer resets in a cliff. One
 * string per key holds the theoretical arrival time (TAT, ms). Time comes from the server
 * (`TIME`), so replica clock skew cannot move a limit. A denied check does not move the
 * TAT. As before, the throttler's `blockDuration` still holds a caller that went over its limit
 * for that long (a separate key); with `blockDuration` 0 the caller is admitted again as soon as
 * one interval has passed.
 */
const GCRA_SCRIPT = `
local key = KEYS[1]
local blockKey = KEYS[2]
local ttl = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local blockDuration = tonumber(ARGV[3])

local blockLeft = redis.call("PTTL", blockKey)
if blockLeft > 0 then
  return {limit + 1, 0, 1, blockLeft}
end

local t = redis.call("TIME")
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local interval = ttl / limit

local tat = tonumber(redis.call("GET", key))
if tat == nil or tat < now then tat = now end

local newTat = tat + interval
local allowAt = newTat - ttl
if now < allowAt then
  local wait = math.ceil(allowAt - now)
  if blockDuration > 0 then
    redis.call("SET", blockKey, "1", "PX", blockDuration)
    wait = blockDuration
  end
  return {limit + 1, math.ceil(tat - now), 1, wait}
end

redis.call("SET", key, string.format("%.3f", newTat), "PX", math.ceil(newTat - now) + 1000)
return {math.ceil((newTat - now) / interval), math.ceil(newTat - now), 0, 0}
`;

/**
 * Phase 12a (Redis-backed rate limiting, decision #76). The `@nestjs/
 * throttler`-documented extension point (`ThrottlerStorage`) implemented
 * against this codebase's existing `redis` (node-redis) client — Redis
 * already exists in this deployment (Phase 9b, `RedisPubSubService`) —
 * rather than pulling in a community package that expects `ioredis`
 * (`nestjs-throttler-storage-redis`/`@nest-lab/throttler-storage-redis`),
 * which would mean two different Redis client libraries in one codebase
 * for no real benefit.
 *
 * A single shared connection (mirroring `RedisPubSubService`'s own
 * "best-effort connect at boot, never fails app startup" posture) — this
 * is what makes rate limiting actually correct across every replica of
 * either Nest application (`AppModule`/`AgentMtlsAppModule`): an
 * in-memory-only store (`@nestjs/throttler`'s own default) would let each
 * replica enforce its own separate limit, defeating the point.
 */
@Injectable()
export class RedisThrottlerStorageService
  implements ThrottlerStorage, OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(RedisThrottlerStorageService.name);
  private readonly redis: BoundedRedis;

  constructor(configService: ConfigService<AppConfig, true>) {
    this.redis = new BoundedRedis(
      redisClientOptions((key) => configService.get(key, { infer: true })),
      configService.get('REDIS_TIMEOUT_MS', { infer: true }),
      this.logger,
      'Rate-limit store',
    );
  }

  async onModuleInit(): Promise<void> {
    try {
      await this.redis.connect();
    } catch (error) {
      this.logger.warn(
        `Could not connect to Redis at startup (will retry lazily on first increment): ${errorMessage(error)}`,
      );
    }
  }

  async onModuleDestroy(): Promise<void> {
    await this.redis.close();
  }

  /**
   * `ThrottlerStorage.increment` — see class doc comment. Namespaced by
   * `throttlerName` (the throttler config's own `name`, `'default'` when
   * unset) so the human and agent surfaces' separately-configured
   * throttlers, even if they somehow shared a Redis instance, could never
   * collide on the same counter key.
   */
  async increment(
    key: string,
    ttl: number,
    limit: number,
    blockDuration: number,
    throttlerName: string,
  ): Promise<ThrottlerStorageRecord> {
    const client = await this.redis.get();
    const redisKey = `manar:throttle:${throttlerName}:${key}`;

    const result = (await client.eval(GCRA_SCRIPT, {
      keys: [redisKey, `${redisKey}:block`],
      arguments: [String(ttl), String(limit), String(blockDuration)],
    })) as [number, number, number, number];

    const [totalHitsMs, timeToExpireMs, isBlocked, timeToBlockExpireMs] =
      result;
    return {
      totalHits: totalHitsMs,
      timeToExpire: Math.max(0, Math.ceil(timeToExpireMs / 1000)),
      isBlocked: isBlocked === 1,
      timeToBlockExpire: Math.max(0, Math.ceil(timeToBlockExpireMs / 1000)),
    };
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
