import { Module } from '@nestjs/common';
import { ApprovalsModule } from './approvals.module';
import { ApprovalsController } from './approvals.controller';
import { ToolsModule } from '../tools/tools.module';

/** The human-facing `/approvals` HTTP surface — split from `ApprovalsModule` (providers-only) for the same reason `PolicyHttpModule`/`TasksHttpModule` are. Imported only into `AppModule`. */
@Module({
  imports: [ApprovalsModule, ToolsModule],
  controllers: [ApprovalsController],
})
export class ApprovalsHttpModule {}
