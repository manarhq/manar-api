import { Module } from '@nestjs/common';
import { AppConfigModule } from '../config/config.module';
import { DatabaseModule } from '../database/database.module';
import { KeycloakModule } from '../keycloak/keycloak.module';
import { OpenSearchIndexModule } from '../audit/opensearch/opensearch-index.module';
import { TenantCreateCommand } from './commands/tenant-create.command';
import { AuditReindexCommand } from './commands/audit-reindex.command';

/**
 * Root module for the `pnpm manar` CLI (see src/cli.ts). Deliberately
 * separate from AppModule: the CLI needs config + the database layer +
 * Keycloak provisioning + (Phase 9b) the OpenSearch reindex path, but not
 * HTTP (Fastify adapter, health endpoints, request logging/correlation-ID
 * middleware, auth guards) or the live Kafka consumer
 * (`AuditIndexerModule`, `AppModule`-only — see that module's doc
 * comment).
 */
@Module({
  imports: [
    AppConfigModule,
    DatabaseModule,
    KeycloakModule,
    OpenSearchIndexModule,
  ],
  providers: [TenantCreateCommand, AuditReindexCommand],
})
export class CliModule {}
