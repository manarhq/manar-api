import { Global, Module } from '@nestjs/common';
import { IdempotencyStoreService } from './idempotency-store.service';
import { IdempotencyInterceptor } from './idempotency.interceptor';

/**
 * `@Global()`, same posture as `KillSwitchesModule` — `IdempotencyInterceptor`
 * is applied per-route across several otherwise-unrelated controllers
 * (agents, policy, kill-switches, webhooks), so every application graph
 * that mounts any of those needs it available without each one importing
 * this module by hand at every call site.
 */
@Global()
@Module({
  providers: [IdempotencyStoreService, IdempotencyInterceptor],
  exports: [IdempotencyStoreService, IdempotencyInterceptor],
})
export class IdempotencyModule {}
