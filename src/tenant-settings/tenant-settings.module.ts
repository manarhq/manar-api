import { Module } from '@nestjs/common';
import { TenantSettingsController } from './tenant-settings.controller';
import { TenantSettingsService } from './tenant-settings.service';

/**
 * Phase 14 (Users/Roles/Settings) — the `/tenant/settings` HTTP surface.
 * `ControlPrismaService`/`AuditService`/`TenantDatabaseManager` are all
 * `@Global()`, so nothing else needs importing here. Imported only into
 * `AppModule`.
 */
@Module({
  controllers: [TenantSettingsController],
  providers: [TenantSettingsService],
})
export class TenantSettingsModule {}
