import { Module } from '@nestjs/common';
import { ApproverDirectory } from '../approvals/approver-directory';
import { PushService } from './push.service';

/** Web Push sending, providers only (the mTLS app must not expose the console routes). */
@Module({
  providers: [PushService, ApproverDirectory],
  exports: [PushService, ApproverDirectory],
})
export class PushModule {}
