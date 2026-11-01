import { Module } from '@nestjs/common';
import { HostApprovalsModule } from '../approvals/host-approvals.module';
import { HostMtlsModule } from '../host-mtls/host-mtls.module';
import { JailConsoleController } from './jail-console.controller';
import { JailHostController } from './jail-host.controller';
import { JailSitesService } from './jail-sites.service';

/** `POST /host/v1/jail/ask` on the mTLS listener; imported by the mTLS app only. */
@Module({
  imports: [HostMtlsModule, HostApprovalsModule],
  controllers: [JailHostController],
})
export class JailMtlsModule {}

/** Console routes `/jail/site-rules`; imported by the human-facing app only. */
@Module({
  controllers: [JailConsoleController],
  providers: [JailSitesService],
})
export class JailHttpModule {}
