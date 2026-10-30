import { Module } from '@nestjs/common';
import { PublicReportController } from './public-report.controller';
import { ReportCardController } from './report-card.controller';
import { ReportCardService } from './report-card.service';
import { ReportShareService } from './report-share.service';
import { SampleController } from './sample.controller';
import { SampleService } from './sample.service';
import {
  SAMPLE_DIRECTORY,
  WORKSPACE_PROVISIONING,
  stubDirectory,
  stubProvisioning,
} from './workspace-provisioning.port';
import { StartModeController } from './start-mode.controller';
import { StartModeService } from './start-mode.service';

/** Features track: start mode, sample workspace and the weekly report card. HTTP app only. */
@Module({
  controllers: [
    StartModeController,
    ReportCardController,
    PublicReportController,
    SampleController,
  ],
  providers: [
    StartModeService,
    ReportCardService,
    ReportShareService,
    SampleService,
    // Stubs until the identity track's WorkspaceProvisioningService is on main (see the port).
    { provide: WORKSPACE_PROVISIONING, useValue: stubProvisioning },
    { provide: SAMPLE_DIRECTORY, useValue: stubDirectory },
  ],
})
export class WorkspaceModule {}
