import { Module } from '@nestjs/common';
import {
  HostOrganisationController,
  HostsController,
  InstallKeysController,
} from './hosts-admin.controller';
import { AdcsAdminController } from './adcs/adcs-admin.controller';
import { HostRegisterController } from './host-register.controller';
import { FileChangesModule } from './changes/file-changes.module';
import { HostsModule } from './hosts.module';

@Module({
  imports: [HostsModule, FileChangesModule],
  controllers: [
    HostRegisterController,
    HostsController,
    InstallKeysController,
    HostOrganisationController,
    AdcsAdminController,
  ],
})
export class HostsHttpModule {}
