import { Module } from '@nestjs/common';
import { TasksModule } from './tasks.module';
import { TasksController } from './tasks.controller';

/** The human-facing `/tasks` HTTP surface — split from `TasksModule` (services-only) for the same reason `AgentsHttpModule` is; see that module's doc comment. Imported only into `AppModule`. */
@Module({
  imports: [TasksModule],
  controllers: [TasksController],
})
export class TasksHttpModule {}
