import { Module } from '@nestjs/common';
import { AiAdvisoryModule } from '../ai-advisory/ai-advisory.module';
import { ToolsModule } from '../tools/tools.module';
import { IncidentsController } from './incidents.controller';
import { IncidentsService } from './incidents.service';

/**
 * Phase 15a (Section 70) — the `/incidents` HTTP surface. `AuditService`/
 * `TenantDatabaseManager` are both `@Global()` (see `AuditModule`/
 * `DatabaseModule`'s own doc comments), so nothing else needs importing
 * here — mirrors `UsersModule`'s identical single-module shape. Imported
 * only into `AppModule`.
 *
 * Phase 10c: imports `AiAdvisoryModule` (`AiAdvisoryClient`, for
 * `summarizeIncident`) and `ToolsModule` (`ToolRegistryService`, to
 * resolve each included `AuditEvent`'s `ToolAction.classification` for the
 * data-residency gate) — same two-import shape `PolicyModule`/`RiskModule`
 * already establish for the identical dependency pair.
 */
@Module({
  imports: [AiAdvisoryModule, ToolsModule],
  controllers: [IncidentsController],
  providers: [IncidentsService],
})
export class IncidentsModule {}
