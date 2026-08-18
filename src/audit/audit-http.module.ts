import { Module } from '@nestjs/common';
import { AuditModule } from './audit.module';
import { AuditController } from './audit.controller';

/** The human-facing `/audit` HTTP surface — split from `AuditModule` (providers-only, `@Global()`) for the same reason `PolicyHttpModule`/`TasksHttpModule` are. Imported only into `AppModule`. */
@Module({
  imports: [AuditModule],
  controllers: [AuditController],
})
export class AuditHttpModule {}
