import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerModule } from '@nestjs/throttler';
import type { AppConfig } from '../config/env.validation';
import { RedisThrottlerStorageService } from './redis-throttler-storage.service';
import { RedisThrottlerStorageModule } from './redis-throttler-storage.module';
import { AgentThrottlerGuard } from './agent-throttler.guard';

/**
 * Phase 12a: the mTLS `/agent/v1/*` surface's rate limiting
 * (`AgentMtlsAppModule` only -- see `RateLimitModule` for the separate,
 * differently-scoped human JWT surface). A wholly separate `ThrottlerModule`
 * registration from the human app's -- each `NestFactory.create()` call
 * gets its own DI container (the same "global only means global within one
 * application's module graph" caveat every other cross-cutting module in
 * this codebase documents), so this is not optional boilerplate: without
 * it, this listener would have no rate limiting at all.
 */
@Module({
  imports: [
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
            name: 'agent',
            ttl: configService.get('RATE_LIMIT_AGENT_TTL_MS', { infer: true }),
            limit: configService.get('RATE_LIMIT_AGENT_LIMIT', { infer: true }),
          },
        ],
      }),
    }),
  ],
  providers: [{ provide: APP_GUARD, useClass: AgentThrottlerGuard }],
})
export class AgentRateLimitModule {}
