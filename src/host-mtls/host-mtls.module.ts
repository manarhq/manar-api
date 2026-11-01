import { Module } from '@nestjs/common';
import { HostAuthGuard } from './host-auth.guard';
import { HostToolsService } from '../host-coverage/host-tools.service';
import { AiSpendService } from '../ai-spend/ai-spend.service';
import { HostConfigController } from './host-config.controller';

/** `/host/v1/*` on the mTLS listener. Other tracks add their controllers and `@UseGuards(HostAuthGuard)`. */
@Module({
  controllers: [HostConfigController],
  providers: [HostAuthGuard, HostToolsService, AiSpendService],
  exports: [HostAuthGuard, HostToolsService, AiSpendService],
})
export class HostMtlsModule {}
