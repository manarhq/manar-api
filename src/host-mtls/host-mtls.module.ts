import { Module } from '@nestjs/common';
import { HostAuthGuard } from './host-auth.guard';
import { HostToolsService } from '../host-coverage/host-tools.service';
import { FileChangesModule } from '../hosts/changes/file-changes.module';
import { HostChangesController } from '../hosts/changes/host-changes.controller';
import { HostConfigController } from './host-config.controller';

/** `/host/v1/*` on the mTLS listener. Other tracks add their controllers and `@UseGuards(HostAuthGuard)`. */
@Module({
  imports: [FileChangesModule],
  controllers: [HostConfigController, HostChangesController],
  providers: [HostAuthGuard, HostToolsService],
  exports: [HostAuthGuard, HostToolsService],
})
export class HostMtlsModule {}
