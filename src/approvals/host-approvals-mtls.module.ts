import { Module } from '@nestjs/common';
import { HostMtlsModule } from '../host-mtls/host-mtls.module';
import { HostApprovalsController } from './host-approvals.controller';
import { HostApprovalsModule } from './host-approvals.module';

/** `/host/v1/approvals/*` on the mTLS listener. Imported only into `AgentMtlsAppModule`. */
@Module({
  imports: [HostMtlsModule, HostApprovalsModule],
  controllers: [HostApprovalsController],
})
export class HostApprovalsMtlsModule {}
