import { Module } from '@nestjs/common';
import {
  HostOrganisationController,
  HostsController,
  InstallKeysController,
} from './hosts-admin.controller';
import { AdcsAdminController } from './adcs/adcs-admin.controller';
import { HostRegisterController } from './host-register.controller';
import { HostsModule } from './hosts.module';

@Module({
  imports: [HostsModule],
  controllers: [
    HostRegisterController,
    HostsController,
    InstallKeysController,
    HostOrganisationController,
    AdcsAdminController,
  ],
})
export class HostsHttpModule {}
