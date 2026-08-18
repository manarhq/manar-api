import { Module } from '@nestjs/common';
import { AppConfigModule } from '../config/config.module';
import { DatabaseModule } from '../database/database.module';
import { TenantCreateCommand } from './commands/tenant-create.command';

/**
 * Root module for the `pnpm manar` CLI (see src/cli.ts). Deliberately
 * separate from AppModule: the CLI needs config + the database layer, but
 * not HTTP (Fastify adapter, health endpoints, request logging/
 * correlation-ID middleware).
 */
@Module({
  imports: [AppConfigModule, DatabaseModule],
  providers: [TenantCreateCommand],
})
export class CliModule {}
