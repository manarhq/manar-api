import { Module } from '@nestjs/common';
import { ApproverDirectory } from '../approvals/approver-directory';
import { TelegramService } from './telegram.service';

/** Telegram sending and link state, providers only (the mTLS app opens approvals and must send). */
@Module({
  providers: [TelegramService, ApproverDirectory],
  exports: [TelegramService],
})
export class TelegramModule {}
