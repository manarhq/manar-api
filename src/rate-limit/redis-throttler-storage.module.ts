import { Module } from '@nestjs/common';
import { RedisThrottlerStorageService } from './redis-throttler-storage.service';

/**
 * A dedicated module purely so `RedisThrottlerStorageService` can be
 * listed in `ThrottlerModule.forRootAsync({ imports: [...] })` — Nest's
 * dynamic-module `useFactory`/`inject` resolves its `inject` tokens from
 * the dynamic module's OWN `imports`, not from whatever sibling module
 * happens to also declare that provider (`RateLimitModule`/
 * `AgentRateLimitModule` alike would otherwise fail to resolve this at
 * `ThrottlerModule`'s own instantiation time, even though the provider is
 * "right there" in the surrounding module). `ConfigService` resolves fine
 * without an equivalent module because `@nestjs/config`'s `ConfigModule`
 * is already global.
 */
@Module({
  providers: [RedisThrottlerStorageService],
  exports: [RedisThrottlerStorageService],
})
export class RedisThrottlerStorageModule {}
