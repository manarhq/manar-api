import { Module } from '@nestjs/common';
import { EntitlementsModule } from '../entitlements/entitlements.module';
import { HostsModule } from '../hosts/hosts.module';
import { DevicesController } from './devices.controller';
import { DevicesService } from './devices.service';
import { InstallController } from './install.controller';

/** "Add device" (console) and the public install scripts. */
@Module({
  imports: [HostsModule, EntitlementsModule],
  controllers: [DevicesController, InstallController],
  providers: [DevicesService],
})
export class DevicesHttpModule {}
