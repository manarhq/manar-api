import { Module } from '@nestjs/common';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';

/**
 * Phase 14 (Users/Roles/Settings) — the `/users` HTTP surface.
 * `AuditService`/`ControlPrismaService`/`KeycloakAdminClient`/
 * `TenantDatabaseManager` are all `@Global()` (see `AuditModule`/
 * `DatabaseModule`/`KeycloakModule`'s own doc comments), so nothing else
 * needs importing here. Imported only into `AppModule` — this surface has
 * no business existing on the mTLS agent listener.
 */
@Module({
  controllers: [UsersController],
  providers: [UsersService],
})
export class UsersModule {}
