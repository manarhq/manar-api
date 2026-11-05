import { Module } from '@nestjs/common';
import { AiAdvisoryModule } from '../ai-advisory/ai-advisory.module';
import { PolicyModule } from './policy.module';
import { PolicyController } from './policy.controller';

/** The human-facing `/policies` HTTP surface — split from `PolicyModule` (services-only) for the same reason `TasksHttpModule`/`AgentsHttpModule` are. Imported only into `AppModule`. */
@Module({
  imports: [PolicyModule, AiAdvisoryModule],
  controllers: [PolicyController],
})
export class PolicyHttpModule {}
