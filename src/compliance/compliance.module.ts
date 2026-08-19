import { Module } from '@nestjs/common';
import { ComplianceController } from './compliance.controller';
import { ComplianceService } from './compliance.service';

/**
 * Phase 15a (Section 55) — the `/compliance` HTTP surface. `TenantDatabaseManager`
 * is `@Global()` (see `DatabaseModule`'s own doc comment), so nothing else
 * needs importing here — mirrors `UsersModule`'s identical single-module
 * shape (no other consumer needs `ComplianceService`, so no providers-only/
 * HTTP split like `ToolsModule`/`ToolsHttpModule`). Imported only into
 * `AppModule` — this surface has no business existing on the mTLS agent
 * listener.
 */
@Module({
  controllers: [ComplianceController],
  providers: [ComplianceService],
})
export class ComplianceModule {}
