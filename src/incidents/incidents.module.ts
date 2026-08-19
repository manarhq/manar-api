import { Module } from '@nestjs/common';
import { IncidentsController } from './incidents.controller';
import { IncidentsService } from './incidents.service';

/**
 * Phase 15a (Section 70) — the `/incidents` HTTP surface. `AuditService`/
 * `TenantDatabaseManager` are both `@Global()` (see `AuditModule`/
 * `DatabaseModule`'s own doc comments), so nothing else needs importing
 * here — mirrors `UsersModule`'s identical single-module shape. Imported
 * only into `AppModule`.
 */
@Module({
  controllers: [IncidentsController],
  providers: [IncidentsService],
})
export class IncidentsModule {}
