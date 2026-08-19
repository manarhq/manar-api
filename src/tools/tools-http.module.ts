import { Module } from '@nestjs/common';
import { ToolsModule } from './tools.module';
import { ToolsController } from './tools.controller';

/** The human-facing `/tools` HTTP surface (Phase 11b Part 1) — split from `ToolsModule` (providers-only) for the same reason `KillSwitchesHttpModule`/`PolicyHttpModule`/etc. are. Imported only into `AppModule`. */
@Module({
  imports: [ToolsModule],
  controllers: [ToolsController],
})
export class ToolsHttpModule {}
