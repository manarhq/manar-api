import { Module } from '@nestjs/common';
import { StartModeController } from './start-mode.controller';
import { StartModeService } from './start-mode.service';

/** Features track: start mode, sample workspace and the weekly report card. HTTP app only. */
@Module({
  controllers: [StartModeController],
  providers: [StartModeService],
})
export class WorkspaceModule {}
