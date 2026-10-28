import { Module } from '@nestjs/common';
import { HostRegisterController } from './host-register.controller';
import { HostsModule } from './hosts.module';

@Module({
  imports: [HostsModule],
  controllers: [HostRegisterController],
})
export class HostsHttpModule {}
