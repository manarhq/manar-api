import { Module } from '@nestjs/common';
import { AiAdvisoryModule } from '../ai-advisory/ai-advisory.module';
import { PolicyModule } from './policy.module';
import { PolicyController } from './policy.controller';
import { AiJobsModule } from '../ai-jobs/ai-jobs.module';
import { PolicySuggestJobsService } from './policy-suggest-jobs.service';

/** The human-facing `/policies` HTTP surface — split from `PolicyModule` (services-only) for the same reason `TasksHttpModule`/`AgentsHttpModule` are. Imported only into `AppModule`. */
@Module({
  imports: [PolicyModule, AiAdvisoryModule, AiJobsModule],
  controllers: [PolicyController],
  providers: [PolicySuggestJobsService],
})
export class PolicyHttpModule {}
