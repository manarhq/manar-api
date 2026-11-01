import { Module } from '@nestjs/common';
import { PublicReportController } from './public-report.controller';
import { ReportCardController } from './report-card.controller';
import { ReportCardService } from './report-card.service';
import { ReportShareService } from './report-share.service';
import { SampleController } from './sample.controller';
import { SampleService } from './sample.service';
import { WorkspacesModule } from '../workspaces/workspaces.module';
import { StartModeController } from './start-mode.controller';
import { StartModeService } from './start-mode.service';
import { SessionsController } from '../sessions/sessions.controller';
import { SessionsService } from '../sessions/sessions.service';

/** Features track: start mode, sample workspace and the weekly report card. HTTP app only. */
@Module({
  imports: [WorkspacesModule],
  controllers: [
    StartModeController,
    ReportCardController,
    PublicReportController,
    SampleController,
    SessionsController,
  ],
  providers: [
    StartModeService,
    ReportCardService,
    ReportShareService,
    SampleService,
    SessionsService,
  ],
})
export class WorkspaceModule {}
