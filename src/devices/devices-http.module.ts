import { Module } from '@nestjs/common';
import { HostsModule } from '../hosts/hosts.module';
import { DevicesController } from './devices.controller';
import { DevicesService } from './devices.service';
import { InstallController } from './install.controller';

/** "Add device" (console) and the public install scripts. */
@Module({
  imports: [HostsModule],
  controllers: [DevicesController, InstallController],
  providers: [DevicesService],
})
export class DevicesHttpModule {}
