import { Module } from '@nestjs/common';
import { AgentsModule } from '../agents/agents.module';
import { HostsAdminService } from './hosts-admin.service';
import { HostsService } from './hosts.service';
import { InstallKeysService } from './install-keys.service';

/** Hosts (docs/hosts.md): services only; HTTP controllers are in `HostsHttpModule`. */
@Module({
  imports: [AgentsModule],
  providers: [HostsService, InstallKeysService, HostsAdminService],
  exports: [HostsService, InstallKeysService, HostsAdminService],
})
export class HostsModule {}
