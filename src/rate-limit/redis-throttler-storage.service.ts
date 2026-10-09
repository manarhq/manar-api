import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { ThrottlerStorage } from '@nestjs/throttler';
import type { AppConfig } from '../config/env.validation';
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
 * A single Redis hash per key (`hits`/`expiresAt`/`blockExpiresAt`/
 * `blocked`, all epoch-ms) rather than two independent string keys with
 * independent TTLs — deliberately mirrors `@nestjs/throttler`'s own
 * built-in in-memory `ThrottlerStorageService` field-for-field (see that
 * class's source), including its exact "once blocked, stop counting new
 * hits until the block itself expires, then reset the whole record and
 * count this call as hit 1" behavior. An earlier version of this script
 * used two independent keys (a hit counter with its own TTL, a separate
 * block flag with its own TTL) and had a real bug: once the *block* key
 * expired but the *counter* key's longer TTL hadn't, every next request
 * still saw `totalHits > limit` and immediately re-blocked forever within
 * the counter's own window — this single-hash design (with the current
 * timestamp passed in from the client, `ARGV[1]`, so the script's own
 * decisions are anchored to one consistent "now" instead of drifting
 * across multiple `TIME`/`PTTL` calls) is what `redis-throttler-storage.service.spec.ts`'s
 * "the block expires ... no longer blocked" test exists to prove doesn't
 * regress.
 */
const INCREMENT_SCRIPT = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local blockDuration = tonumber(ARGV[4])

local data = redis.call("HMGET", key, "hits", "expiresAt", "blockExpiresAt", "blocked")
local hits = tonumber(data[1])
local expiresAt = tonumber(data[2])
local blockExpiresAt = tonumber(data[3])
local blocked = data[4] == "1"

if hits == nil then
  hits = 0
  expiresAt = now + ttl
  blockExpiresAt = 0
  blocked = false
end

if expiresAt <= now then
  expiresAt = now + ttl
end

if not blocked then
  hits = hits + 1
end

if hits > limit and not blocked then
  blocked = true
  blockExpiresAt = now + blockDuration
end

if blocked and blockExpiresAt <= now then
  hits = 1
  expiresAt = now + ttl
  blocked = false
  blockExpiresAt = 0
end

redis.call("HMSET", key, "hits", hits, "expiresAt", expiresAt, "blockExpiresAt", blockExpiresAt, "blocked", blocked and "1" or "0")

local keyTtlMs = math.max(expiresAt, blockExpiresAt) - now
if keyTtlMs < 1000 then keyTtlMs = 1000 end
redis.call("PEXPIRE", key, keyTtlMs)

local timeToExpire = expiresAt - now
if timeToExpire < 0 then timeToExpire = 0 end
local timeToBlockExpire = 0
if blocked then
  timeToBlockExpire = blockExpiresAt - now
  if timeToBlockExpire < 0 then timeToBlockExpire = 0 end
end

return {hits, timeToExpire, blocked and 1 or 0, timeToBlockExpire}
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
      configService.get('REDIS_URL', { infer: true }),
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

    const result = (await client.eval(INCREMENT_SCRIPT, {
      keys: [redisKey],
      arguments: [
        String(Date.now()),
        String(ttl),
        String(limit),
        String(blockDuration),
      ],
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
