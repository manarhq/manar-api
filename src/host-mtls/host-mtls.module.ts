import { Module } from '@nestjs/common';
import { HostAuthGuard } from './host-auth.guard';
import { HostToolsService } from '../host-coverage/host-tools.service';
import { SecretsModule } from '../secrets/secrets.module';
import { HostConfigController } from './host-config.controller';

/** `/host/v1/*` on the mTLS listener. Other tracks add their controllers and `@UseGuards(HostAuthGuard)`. */
@Module({
  imports: [SecretsModule],
  controllers: [HostConfigController],
  providers: [HostAuthGuard, HostToolsService],
  exports: [HostAuthGuard, HostToolsService],
})
export class HostMtlsModule {}
