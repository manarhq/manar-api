import { Module } from '@nestjs/common';
import { HostAuthGuard } from './host-auth.guard';
import { RestrictionEnforcement } from '../staff/restrictions/restriction-enforcement';
import { HostToolsService } from '../host-coverage/host-tools.service';
import { PauseModule } from '../pause/pause.module';
import { AiSpendService } from '../ai-spend/ai-spend.service';
import { SecretsModule } from '../secrets/secrets.module';
import { FileChangesModule } from '../hosts/changes/file-changes.module';
import { HostChangesController } from '../hosts/changes/host-changes.controller';
import { JailSitesService } from '../jail/jail-sites.service';
import { DataCollectionHostController } from '../data-collection/data-collection-host.controller';
import { DataCollectionModule } from '../data-collection/data-collection.module';
import { HostConfigController } from './host-config.controller';
import { HostsModule } from '../hosts/hosts.module';
import { BillingModule } from '../billing/billing.module';

/** `/host/v1/*` on the mTLS listener. Other tracks add their controllers and `@UseGuards(HostAuthGuard)`. */
@Module({
  imports: [
    PauseModule,
    SecretsModule,
    FileChangesModule,
    DataCollectionModule,
    // "This device moved to another workspace" (POST /host/v1/moved). HostsModule's services need
    // EntitlementsService (BillingModule), which the mTLS app does not otherwise load.
    BillingModule,
    HostsModule,
  ],
  controllers: [
    HostConfigController,
    HostChangesController,
    DataCollectionHostController,
  ],
  providers: [
    HostAuthGuard,
    // The guard's restriction check (DESK spec §9.2); only needs the control database.
    RestrictionEnforcement,
    HostToolsService,
    AiSpendService,
    JailSitesService,
  ],
  exports: [HostAuthGuard, HostToolsService, AiSpendService, JailSitesService],
})
export class HostMtlsModule {}
