import { Module } from '@nestjs/common';
import { WebhooksModule } from './webhooks.module';
import { WebhooksController } from './webhooks.controller';

/** The human-facing webhook admin HTTP surface — split from `WebhooksModule` (providers-only) for the same reason `KillSwitchesHttpModule`/`PolicyHttpModule`/etc. are. Imported only into `AppModule`. */
@Module({
  imports: [WebhooksModule],
  controllers: [WebhooksController],
})
export class WebhooksHttpModule {}
