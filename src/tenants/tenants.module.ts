import { Module } from '@nestjs/common';
import { TenantsController } from './tenants.controller';
import { TenantsService } from './tenants.service';

/**
 * Phase 11b Part 1 — the OIDC-config resolution surface (see
 * `TenantsController`'s doc comment). `ControlPrismaService` is already
 * global (`DatabaseModule`), so nothing else needs importing here.
 * Imported only into `AppModule` — this surface has no business existing
 * on the mTLS agent listener.
 */
@Module({
  controllers: [TenantsController],
  providers: [TenantsService],
})
export class TenantsModule {}
