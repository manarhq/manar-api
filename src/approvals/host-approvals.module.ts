import { Module } from '@nestjs/common';
import { HOST_APPROVAL_OPENER } from '../host-coverage/host-authorize.service';
import { PushModule } from '../push/push.module';
import { HostApprovalOpenerService } from './host-approval-opener.service';
import { HostApprovalsService } from './host-approvals.service';

/**
 * Device approvals, providers only. Also binds `HOST_APPROVAL_OPENER`, which `POST /host/v1/authorize`
 * calls when the answer is "ask" (the coverage track defines the token).
 */
@Module({
  imports: [PushModule],
  providers: [
    HostApprovalsService,
    { provide: HOST_APPROVAL_OPENER, useClass: HostApprovalOpenerService },
  ],
  exports: [HostApprovalsService, HOST_APPROVAL_OPENER],
})
export class HostApprovalsModule {}
