import { Module } from '@nestjs/common';
import { HostAuthGuard } from './host-auth.guard';
import { HostToolsService } from '../host-coverage/host-tools.service';
import { JailSitesService } from '../jail/jail-sites.service';
import { HostConfigController } from './host-config.controller';

/** `/host/v1/*` on the mTLS listener. Other tracks add their controllers and `@UseGuards(HostAuthGuard)`. */
@Module({
  controllers: [HostConfigController],
  providers: [HostAuthGuard, HostToolsService, JailSitesService],
  exports: [HostAuthGuard, HostToolsService, JailSitesService],
})
export class HostMtlsModule {}
