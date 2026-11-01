import { Module } from '@nestjs/common';
import { ApproverDirectory } from '../approvals/approver-directory';
import { TelegramModule } from '../telegram/telegram.module';
import { PushService } from './push.service';

/** Web Push sending, providers only (the mTLS app must not expose the console routes). */
@Module({
  imports: [TelegramModule],
  providers: [PushService, ApproverDirectory],
  exports: [PushService, ApproverDirectory, TelegramModule],
})
export class PushModule {}
