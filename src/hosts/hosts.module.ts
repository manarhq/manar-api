import { Module } from '@nestjs/common';
import { AgentsModule } from '../agents/agents.module';
import { HostsService } from './hosts.service';
import { InstallKeysService } from './install-keys.service';

/** Hosts (docs/hosts.md): services only; HTTP controllers are in `HostsHttpModule`. */
@Module({
  imports: [AgentsModule],
  providers: [HostsService, InstallKeysService],
  exports: [HostsService, InstallKeysService],
})
export class HostsModule {}
