import { RedisThrottlerStorageModule } from '../rate-limit/redis-throttler-storage.module';
import { Module } from '@nestjs/common';
import { AppConfigModule } from '../config/config.module';
import { DatabaseModule } from '../database/database.module';
import { KeycloakModule } from '../keycloak/keycloak.module';
import { OpenSearchIndexModule } from '../audit/opensearch/opensearch-index.module';
import { TenantCreateCommand } from './commands/tenant-create.command';
import { AuditReindexCommand } from './commands/audit-reindex.command';
import { AuditModule } from '../audit/audit.module';
import { AuditBenchCommand } from './commands/audit-bench.command';
import { AuditVerifyCommand } from './commands/audit-verify.command';
import { AuditService } from '../audit/audit.service';
import { KafkaPublisherService } from '../audit/kafka-publisher.service';
import { DemoSeedCommand } from './commands/demo-seed.command';
import { TenantsMigrateCommand } from './commands/tenants-migrate.command';
import { ManarConnectorRegisterCommand } from './commands/manar-connector-register.command';
import { MicrosoftRegisterCommand } from './commands/microsoft-register.command';
import { GitLabConnectorRegisterCommand } from './commands/gitlab-connector-register.command';
import { FleetKeygenCommand } from './commands/fleet-keygen.command';
import { FleetReportCommand } from './commands/fleet-report.command';
import { FleetHeartbeatModule } from '../fleet-heartbeat/fleet-heartbeat.module';
import {
  MembershipsGrantCommand,
  MembershipsMigrateCommand,
} from './commands/memberships.command';
import {
  WorkspacesDrainCommand,
  WorkspacesRetryCommand,
} from './commands/workspaces-drain.command';
import { WorkspaceProvisioningService } from '../workspaces/workspace-provisioning.service';
import { LicenseVerifyCommand } from './commands/license-verify.command';
import { BillingRetireLaunchOfferCommand } from './commands/billing-retire-launch-offer.command';
import { AiDefaultOnCommand } from './commands/ai-default-on.command';
import { AiDefaultService } from '../tenant-settings/ai-default.service';
import { StripeGateway } from '../billing/stripe.gateway';

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
    // WorkspaceProvisioningService's creation gate (workspaces:drain never creates).
    RedisThrottlerStorageModule,
    // AuditModule's key lookup and SEAL marks back the CLI's own AuditService.
    AuditModule,
    KeycloakModule,
    OpenSearchIndexModule,
    FleetHeartbeatModule,
  ],
  providers: [
    TenantCreateCommand,
    AuditReindexCommand,
    AuditVerifyCommand,
    AuditBenchCommand,
    // audit:verify only reads the chain; the CLI never publishes audit events.
    AuditService,
    {
      provide: KafkaPublisherService,
      useValue: {
        publish: () =>
          Promise.reject(new Error('the CLI does not publish audit events')),
      },
    },
    DemoSeedCommand,
    TenantsMigrateCommand,
    ManarConnectorRegisterCommand,
    MicrosoftRegisterCommand,
    GitLabConnectorRegisterCommand,
    FleetKeygenCommand,
    FleetReportCommand,
    LicenseVerifyCommand,
    MembershipsMigrateCommand,
    MembershipsGrantCommand,
    WorkspacesDrainCommand,
    WorkspacesRetryCommand,
    WorkspaceProvisioningService,
    BillingRetireLaunchOfferCommand,
    StripeGateway,
    AiDefaultOnCommand,
    AiDefaultService,
  ],
})
export class CliModule {}
