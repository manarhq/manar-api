import { Module } from '@nestjs/common';
import { HostAuthGuard } from './host-auth.guard';
import { HostToolsService } from '../host-coverage/host-tools.service';
import { PauseModule } from '../pause/pause.module';
import { AiSpendService } from '../ai-spend/ai-spend.service';
import { SecretsModule } from '../secrets/secrets.module';
import { FileChangesModule } from '../hosts/changes/file-changes.module';
import { HostChangesController } from '../hosts/changes/host-changes.controller';
import { JailSitesService } from '../jail/jail-sites.service';
import { HostConfigController } from './host-config.controller';

/** `/host/v1/*` on the mTLS listener. Other tracks add their controllers and `@UseGuards(HostAuthGuard)`. */
@Module({
  imports: [PauseModule, SecretsModule, FileChangesModule],
  controllers: [HostConfigController, HostChangesController],
  providers: [
    HostAuthGuard,
    HostToolsService,
    AiSpendService,
    JailSitesService,
  ],
  exports: [HostAuthGuard, HostToolsService, AiSpendService, JailSitesService],
})
export class HostMtlsModule {}
