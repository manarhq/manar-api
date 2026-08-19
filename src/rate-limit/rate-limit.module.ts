import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerModule } from '@nestjs/throttler';
import type { AppConfig } from '../config/env.validation';
import { AuthModule } from '../auth/auth.module';
import { RedisThrottlerStorageService } from './redis-throttler-storage.service';
import { RedisThrottlerStorageModule } from './redis-throttler-storage.module';
import { TenantThrottlerGuard } from './tenant-throttler.guard';

/**
 * Phase 12a: the human-facing JWT surface's rate limiting (`AppModule`
 * only -- see `AgentRateLimitModule` for the separate, differently-scoped
 * mTLS surface). `TenantThrottlerGuard` registered as a global `APP_GUARD`
 * so every route on this application gets it, not just ones that
 * remember to add `@UseGuards(TenantThrottlerGuard)` individually.
 * Imports `AuthModule` for `KnownIssuerRegistry`, which the guard needs to
 * resolve an unverified token's issuer to a real tenant id (see that
 * guard's own doc comment).
 */
@Module({
  imports: [
    AuthModule,
    ThrottlerModule.forRootAsync({
      imports: [RedisThrottlerStorageModule],
      inject: [ConfigService, RedisThrottlerStorageService],
      useFactory: (
        configService: ConfigService<AppConfig, true>,
        storage: RedisThrottlerStorageService,
      ) => ({
        storage,
        throttlers: [
          {
            name: 'human',
            ttl: configService.get('RATE_LIMIT_HUMAN_TTL_MS', { infer: true }),
            limit: configService.get('RATE_LIMIT_HUMAN_LIMIT', { infer: true }),
          },
        ],
      }),
    }),
  ],
  providers: [{ provide: APP_GUARD, useClass: TenantThrottlerGuard }],
})
export class RateLimitModule {}
