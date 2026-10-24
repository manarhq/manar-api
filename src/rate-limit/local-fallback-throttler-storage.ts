import { Logger } from '@nestjs/common';
import {
  ThrottlerStorageService,
  type ThrottlerStorage,
} from '@nestjs/throttler';
import { recordRateLimitFallback } from '../metrics/metrics';

type ThrottlerStorageRecord = Awaited<
  ReturnType<ThrottlerStorage['increment']>
>;

/**
 * The human surface's limits store: Redis, and when Redis is unavailable or
 * slower than REDIS_TIMEOUT_MS, the same limits in this
 * process's memory. Tenant limits never disappear during a Redis outage;
 * they become per replica (with N replicas a tenant gets up to N times its
 * limit until Redis is back). Logged once per outage and exported as
 * manar_rate_limit_fallback_active / _requests_total.
 *
 * The agent surface does not use this: it fails closed (AgentThrottlerGuard).
 */
export class LocalFallbackThrottlerStorage implements ThrottlerStorage {
  private readonly logger = new Logger(LocalFallbackThrottlerStorage.name);
  private readonly local = new ThrottlerStorageService();
  private active = false;

  constructor(
    private readonly primary: ThrottlerStorage,
    private readonly surface: string,
  ) {}

  async increment(
    key: string,
    ttl: number,
    limit: number,
    blockDuration: number,
    throttlerName: string,
  ): Promise<ThrottlerStorageRecord> {
    try {
      const record = await this.primary.increment(
        key,
        ttl,
        limit,
        blockDuration,
        throttlerName,
      );
      if (this.active) {
        this.active = false;
        recordRateLimitFallback(this.surface, false);
        this.logger.warn(
          `Rate-limit store is back; ${this.surface} limits use Redis again`,
        );
      }
      return record;
    } catch (error) {
      if (!this.active) {
        this.active = true;
        this.logger.error(
          `Rate-limit store unavailable; ${this.surface} limits fall back to this instance's memory: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      recordRateLimitFallback(this.surface, true);
      return this.local.increment(
        key,
        ttl,
        limit,
        blockDuration,
        throttlerName,
      );
    }
  }
}
