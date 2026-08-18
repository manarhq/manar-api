import { Global, Module } from '@nestjs/common';
import { ControlPrismaService } from './control-prisma.service';
import { EnvSecretProvider } from './env-secret-provider';
import { SECRET_PROVIDER } from './secret-provider';
import { TenantDatabaseManager } from './tenant-database-manager.service';

/**
 * Wires up the control DB client, the (swappable) SecretProvider, and
 * TenantDatabaseManager. Global because these are cross-cutting
 * infrastructure services every future domain module will depend on — see
 * docs/tenant-isolation.md.
 */
@Global()
@Module({
  providers: [
    ControlPrismaService,
    { provide: SECRET_PROVIDER, useClass: EnvSecretProvider },
    TenantDatabaseManager,
  ],
  exports: [ControlPrismaService, SECRET_PROVIDER, TenantDatabaseManager],
})
export class DatabaseModule {}
