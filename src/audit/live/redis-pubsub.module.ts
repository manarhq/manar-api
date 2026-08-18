import { Module } from '@nestjs/common';
import { RedisPubSubService } from './redis-pubsub.service';

/**
 * `RedisPubSubService` alone (Section 62) — imported by both
 * `AuditIndexerModule` (the publishing side) and `LiveEventsHttpModule`
 * (the subscribing side, `GET /events/live`). Deliberately not
 * `@Global()`: unlike `AuditModule`/`DatabaseModule`, this isn't needed
 * across every domain module in the codebase, only the live-feed ones.
 */
@Module({
  providers: [RedisPubSubService],
  exports: [RedisPubSubService],
})
export class RedisPubSubModule {}
