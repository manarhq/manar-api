import { Module } from '@nestjs/common';
import { AiSystemsController } from './ai-systems.controller';
import { AiSystemsService } from './ai-systems.service';

/**
 * Release 2026-11-11 (brief §3.1) — the `/ai-systems` HTTP surface.
 *
 * `AuditService` and `TenantDatabaseManager` are both `@Global()` (see
 * `AuditModule`/`DatabaseModule`), so nothing needs importing here — the
 * same single-module shape `UsersModule` and `IncidentsModule` use.
 * Deliberately no `AiAdvisoryModule` import: the inventory is a
 * deterministic governance record, and nothing on this surface should be
 * able to depend on an LLM being reachable.
 */
@Module({
  controllers: [AiSystemsController],
  providers: [AiSystemsService],
})
export class AiSystemsModule {}
