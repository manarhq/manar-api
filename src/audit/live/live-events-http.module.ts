import { Module } from '@nestjs/common';
import { RedisPubSubModule } from './redis-pubsub.module';
import { LiveEventsController } from './live-events.controller';

/** The human-facing `/events/live` HTTP surface (Section 62). Imported only into `AppModule`. */
@Module({
  imports: [RedisPubSubModule],
  controllers: [LiveEventsController],
})
export class LiveEventsHttpModule {}
