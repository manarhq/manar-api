import { AiSpendHttpModule } from './ai-spend/ai-spend.module';
import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { JailHttpModule } from './jail/jail.module';
import { APP_FILTER, APP_INTERCEPTOR } from '@nestjs/core';
import {
  ERROR_REFERENCE_SINK,
  ErrorReferenceRecorder,
} from './staff/errors/error-reference.recorder';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AppConfigModule } from './config/config.module';
import { LoggingModule } from './logging/logging.module';
import { CorrelationIdMiddleware } from './logging/correlation-id.middleware';
import { LoggingInterceptor } from './logging/logging.interceptor';
import { ErrorEnvelopeFilter } from './common/errors/error-envelope.filter';
import { HealthModule } from './health/health.module';
import { DatabaseModule } from './database/database.module';
import { AuthModule } from './auth/auth.module';
import { OpenBaoModule } from './openbao/openbao.module';
import { AgentsHttpModule } from './agents/agents-http.module';
import { AiToolsHttpModule } from './host-coverage/host-coverage.module';
import { DevicesHttpModule } from './devices/devices-http.module';
import { SecretsHttpModule } from './secrets/secrets.module';
import { HostsHttpModule } from './hosts/hosts-http.module';
import { AuthorizationModule } from './authorization/authorization.module';
import { TasksModule } from './tasks/tasks.module';
import { TasksHttpModule } from './tasks/tasks-http.module';
import { PolicyHttpModule } from './policy/policy-http.module';
import { TemporalModule } from './temporal/temporal.module';
import { ApprovalsHttpModule } from './approvals/approvals-http.module';
import { PushHttpModule } from './push/push-http.module';
import { TelegramHttpModule } from './telegram/telegram-http.module';
import { AuditModule } from './audit/audit.module';
import { AuditHttpModule } from './audit/audit-http.module';
import { AuditIndexerModule } from './audit/opensearch/audit-indexer.module';
import { LiveEventsHttpModule } from './audit/live/live-events-http.module';
import { EvidenceHttpModule } from './evidence/evidence-http.module';
import { KillSwitchesHttpModule } from './kill-switches/kill-switches-http.module';
import { PauseHttpModule } from './pause/pause-http.module';
import { RateLimitModule } from './rate-limit/rate-limit.module';
import { WebhooksHttpModule } from './webhooks/webhooks-http.module';
import { WebhookDeliveryConsumerModule } from './webhooks/webhook-delivery-consumer.module';
import { IdempotencyModule } from './idempotency/idempotency.module';
import { ToolsHttpModule } from './tools/tools-http.module';
import { TenantsModule } from './tenants/tenants.module';
import { PlatformModule } from './platform/platform.module';
import { CatalogHttpModule } from './platform/catalog.module';
import { FleetHeartbeatModule } from './fleet-heartbeat/fleet-heartbeat.module';
import { BillingHttpModule, BillingModule } from './billing/billing.module';
import { LicensingModule } from './licensing/licensing.module';
import { UsersModule } from './users/users.module';
import { WorkspacesModule } from './workspaces/workspaces.module';
import { TenantSettingsModule } from './tenant-settings/tenant-settings.module';
import { WorkspaceModule } from './workspace/workspace.module';
import { ContactModule } from './contact/contact.module';
import { GrowthModule } from './growth/growth.module';
import { DataCollectionHttpModule } from './data-collection/data-collection.module';
import { KeycloakModule } from './keycloak/keycloak.module';
import { ComplianceModule } from './compliance/compliance.module';
import { IncidentsModule } from './incidents/incidents.module';
import { AiSystemsModule } from './ai-systems/ai-systems.module';
import { AssistantModule } from './assistant/assistant.module';
import { CloudMcpModule } from './cloud-mcp/cloud-mcp.module';
import { EdgeModule } from './edge/edge.module';
import { EdgeHttpModule } from './edge/edge-http.module';

@Module({
  imports: [
    AppConfigModule,
    LoggingModule,
    HealthModule,
    DatabaseModule,
    AuthModule,
    OpenBaoModule,
    AuditModule,
    AgentsHttpModule,
    HostsHttpModule,
    DevicesHttpModule,
    AiToolsHttpModule,
    SecretsHttpModule,
    AiSpendHttpModule,
    JailHttpModule,
    AuthorizationModule,
    TasksModule,
    TasksHttpModule,
    PolicyHttpModule,
    TemporalModule,
    ApprovalsHttpModule,
    PushHttpModule,
    TelegramHttpModule,
    AuditHttpModule,
    AuditIndexerModule,
    LiveEventsHttpModule,
    EvidenceHttpModule,
    KillSwitchesHttpModule,
    PauseHttpModule,
    RateLimitModule,
    WebhooksHttpModule,
    WebhookDeliveryConsumerModule,
    IdempotencyModule,
    ToolsHttpModule,
    TenantsModule,
    PlatformModule,
    CatalogHttpModule,
    FleetHeartbeatModule,
    LicensingModule,
    BillingModule,
    BillingHttpModule,
    // Phase 14: UsersService needs KeycloakAdminClient at runtime (role
    // grant/revoke keeps Keycloak's realm role mappings in sync -- see
    // KeycloakModule's own doc comment for why this module, previously
    // CLI-only, is now also part of the running HTTP app's module graph).
    KeycloakModule,
    UsersModule,
    WorkspacesModule,
    TenantSettingsModule,
    WorkspaceModule,
    ContactModule,
    GrowthModule,
    DataCollectionHttpModule,
    // Phase 15a: Data Classification, Compliance Mapping & Incidents.
    ComplianceModule,
    IncidentsModule,
    // Release 2026-11-11 (brief §3.1): the governed AI-system/use-case
    // inventory — the record findings, investigations, assessments, and
    // evidence attach to.
    AiSystemsModule,
    // Read-only console assistant (ADR-0008); never on the decision path.
    AssistantModule,
    // Public OAuth MCP endpoint for cloud agents (docs/cloud-agents.md); off by default.
    CloudMcpModule,
    // docs/edge.md: edge peer registry, gateway sync API, egress allow-list.
    EdgeModule,
    EdgeHttpModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    { provide: APP_INTERCEPTOR, useClass: LoggingInterceptor },
    ErrorReferenceRecorder,
    { provide: ERROR_REFERENCE_SINK, useExisting: ErrorReferenceRecorder },
    { provide: APP_FILTER, useClass: ErrorEnvelopeFilter },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(CorrelationIdMiddleware).forRoutes('*');
  }
}
