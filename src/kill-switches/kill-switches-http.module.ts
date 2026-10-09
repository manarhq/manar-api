import { Module } from '@nestjs/common';
import { KillSwitchesModule } from './kill-switches.module';
import { KillSwitchesController } from './kill-switches.controller';
import { AgentQuarantineController } from './agent-quarantine.controller';

/** The human-facing kill-switch admin HTTP surface — split from `KillSwitchesModule` (providers-only) for the same reason `PolicyHttpModule`/`TasksHttpModule`/`ApprovalsHttpModule` are. Imported only into `AppModule`. */
@Module({
  imports: [KillSwitchesModule],
  controllers: [KillSwitchesController, AgentQuarantineController],
})
export class KillSwitchesHttpModule {}
