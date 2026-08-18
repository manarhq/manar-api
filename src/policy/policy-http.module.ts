import { Module } from '@nestjs/common';
import { PolicyModule } from './policy.module';
import { PolicyController } from './policy.controller';

/** The human-facing `/policies` HTTP surface — split from `PolicyModule` (services-only) for the same reason `TasksHttpModule`/`AgentsHttpModule` are. Imported only into `AppModule`. */
@Module({
  imports: [PolicyModule],
  controllers: [PolicyController],
})
export class PolicyHttpModule {}
