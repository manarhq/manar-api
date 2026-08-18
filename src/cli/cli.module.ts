import { Module } from '@nestjs/common';
import { AppConfigModule } from '../config/config.module';
import { DatabaseModule } from '../database/database.module';
import { KeycloakModule } from '../keycloak/keycloak.module';
import { TenantCreateCommand } from './commands/tenant-create.command';

/**
 * Root module for the `pnpm manar` CLI (see src/cli.ts). Deliberately
 * separate from AppModule: the CLI needs config + the database layer +
 * Keycloak provisioning, but not HTTP (Fastify adapter, health endpoints,
 * request logging/correlation-ID middleware, auth guards).
 */
@Module({
  imports: [AppConfigModule, DatabaseModule, KeycloakModule],
  providers: [TenantCreateCommand],
})
export class CliModule {}
