import { Module } from '@nestjs/common';
import { HostAuthGuard } from './host-auth.guard';
import { HostConfigController } from './host-config.controller';

/** `/host/v1/*` on the mTLS listener. Other tracks add their controllers and `@UseGuards(HostAuthGuard)`. */
@Module({
  controllers: [HostConfigController],
  providers: [HostAuthGuard],
  exports: [HostAuthGuard],
})
export class HostMtlsModule {}
