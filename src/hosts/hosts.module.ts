import { Module } from '@nestjs/common';
import { AgentsModule } from '../agents/agents.module';
import { AdDirectory, LdapsAdDirectory } from './adcs/ad-directory.client';
import { AdcsAdminService } from './adcs/adcs-admin.service';
import { AdcsDirectoryService } from './adcs/adcs-directory.service';
import { AdcsEnrolmentService } from './adcs/adcs-enrolment.service';
import { HostsAdminService } from './hosts-admin.service';
import { HostsService } from './hosts.service';
import { InstallKeysService } from './install-keys.service';
import { TpmAttestationService } from './tpm/tpm-attestation.service';

/** Hosts (docs/hosts.md): services only; HTTP controllers are in `HostsHttpModule`. */
@Module({
  imports: [AgentsModule],
  providers: [
    HostsService,
    InstallKeysService,
    HostsAdminService,
    TpmAttestationService,
    AdcsDirectoryService,
    AdcsAdminService,
    AdcsEnrolmentService,
    { provide: AdDirectory, useClass: LdapsAdDirectory },
  ],
  exports: [
    HostsService,
    InstallKeysService,
    HostsAdminService,
    TpmAttestationService,
    AdcsAdminService,
    AdcsEnrolmentService,
  ],
})
export class HostsModule {}
