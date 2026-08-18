import { Global, Module } from '@nestjs/common';
import { OpenBaoModule } from '../openbao/openbao.module';
import { CompositeSecretProvider } from './composite-secret-provider';
import { ControlPrismaService } from './control-prisma.service';
import { EnvSecretProvider } from './env-secret-provider';
import { OpenBaoSecretProvider } from './openbao-secret-provider';
import { SECRET_PROVIDER } from './secret-provider';
import { TenantDatabaseManager } from './tenant-database-manager.service';

/**
 * Wires up the control DB client, the (swappable, and — since Phase 7b —
 * multi-backend) SecretProvider, and TenantDatabaseManager. Global because
 * these are cross-cutting infrastructure services every future domain
 * module will depend on — see docs/tenant-isolation.md. Imports
 * `OpenBaoModule` explicitly (even though it's itself `@Global()`) so this
 * module's own dependency on `OpenBaoKvClient` (via `OpenBaoSecretProvider`)
 * is visible from this file alone, not merely implied by both application
 * root modules happening to import `OpenBaoModule` too.
 */
@Global()
@Module({
  imports: [OpenBaoModule],
  providers: [
    ControlPrismaService,
    EnvSecretProvider,
    OpenBaoSecretProvider,
    { provide: SECRET_PROVIDER, useClass: CompositeSecretProvider },
    TenantDatabaseManager,
  ],
  exports: [ControlPrismaService, SECRET_PROVIDER, TenantDatabaseManager],
})
export class DatabaseModule {}
