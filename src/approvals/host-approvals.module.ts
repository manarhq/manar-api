import { Module } from '@nestjs/common';
import { PushModule } from '../push/push.module';
import { HostApprovalsService } from './host-approvals.service';

/** Device approvals, providers only. Exported for the host authorize path (`open`). */
@Module({
  imports: [PushModule],
  providers: [HostApprovalsService],
  exports: [HostApprovalsService],
})
export class HostApprovalsModule {}
