import { Module } from '@nestjs/common';
import { ApproverDirectory } from '../approvals/approver-directory';
import { HostApprovalsModule } from '../approvals/host-approvals.module';
import { PhoneActionsService } from '../phone/phone-actions.service';
import { PhoneController } from '../phone/phone.controller';
import { TelegramBotHandler } from './telegram-bot.handler';
import {
  TelegramLinkController,
  TelegramWebhookController,
} from './telegram.controller';
import { TelegramModule } from './telegram.module';

/** `/telegram/*` and `/phone/*`. Imported only into `AppModule`. */
@Module({
  imports: [TelegramModule, HostApprovalsModule],
  controllers: [
    TelegramWebhookController,
    TelegramLinkController,
    PhoneController,
  ],
  providers: [TelegramBotHandler, PhoneActionsService, ApproverDirectory],
})
export class TelegramHttpModule {}
