import { Module } from '@nestjs/common';
import { PublicReportController } from './public-report.controller';
import { ReportCardController } from './report-card.controller';
import { ReportCardService } from './report-card.service';
import { ReportShareService } from './report-share.service';
import { StartModeController } from './start-mode.controller';
import { StartModeService } from './start-mode.service';

/** Features track: start mode, sample workspace and the weekly report card. HTTP app only. */
@Module({
  controllers: [
    StartModeController,
    ReportCardController,
    PublicReportController,
  ],
  providers: [StartModeService, ReportCardService, ReportShareService],
})
export class WorkspaceModule {}
