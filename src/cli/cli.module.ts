import { Module } from '@nestjs/common';
import { AppConfigModule } from '../config/config.module';
import { DatabaseModule } from '../database/database.module';
import { KeycloakModule } from '../keycloak/keycloak.module';
import { OpenSearchIndexModule } from '../audit/opensearch/opensearch-index.module';
import { TenantCreateCommand } from './commands/tenant-create.command';
import { AuditReindexCommand } from './commands/audit-reindex.command';
import { DemoSeedCommand } from './commands/demo-seed.command';

/**
 * Root module for the `pnpm manar` CLI (see src/cli.ts). Deliberately
 * separate from AppModule: the CLI needs config + the database layer +
 * Keycloak provisioning + (Phase 9b) the OpenSearch reindex path, but not
 * HTTP (Fastify adapter, health endpoints, request logging/correlation-ID
 * middleware, auth guards) or the live Kafka consumer
 * (`AuditIndexerModule`, `AppModule`-only — see that module's doc
 * comment).
 *
 * `DemoSeedCommand` (Phase 13, Section 85) needs nothing beyond what's
 * already imported here — `TenantProvisioningService`/`KeycloakAdminClient`
 * (Keycloak-only surfaces, `KeycloakModule`), `TenantDatabaseManager`/
 * `OpenBaoKvClient` (both `@Global()`, already part of `DatabaseModule`'s
 * own graph — see that module's doc comment). Everything else it needs
 * (agents, policies, tasks) it drives over real HTTP against an
 * already-running human-facing server, exactly like any other API client,
 * rather than pulling `AgentsModule`/`PolicyModule`/`TasksModule` (and
 * their own Kafka/OpenFGA/Temporal dependencies) into this deliberately
 * HTTP-free application context.
 */
@Module({
  imports: [
    AppConfigModule,
    DatabaseModule,
    KeycloakModule,
    OpenSearchIndexModule,
  ],
  providers: [TenantCreateCommand, AuditReindexCommand, DemoSeedCommand],
})
export class CliModule {}
