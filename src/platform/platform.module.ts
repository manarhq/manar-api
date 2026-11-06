import { Module } from '@nestjs/common';
import { PlatformAuthGuard } from './platform-auth.guard';
import { PlatformOpsController } from './platform-ops.controller';
import { PlatformOpsService } from './platform-ops.service';
import { PlatformController } from './platform.controller';
import { PlatformService } from './platform.service';
import { TenantSectorService } from '../tenant-settings/tenant-sector.service';
import { PlatformSuspension } from './platform-suspension';

/** Imported only into AppModule (the human HTTP app), never the agent mTLS listener. */
@Module({
  controllers: [PlatformController, PlatformOpsController],
  providers: [
    PlatformService,
    PlatformAuthGuard,
    PlatformSuspension,
    PlatformOpsService,
    TenantSectorService,
  ],
})
export class PlatformModule {}
