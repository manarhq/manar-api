import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AppConfigModule } from './config/config.module';
import { LoggingModule } from './logging/logging.module';
import { CorrelationIdMiddleware } from './logging/correlation-id.middleware';
import { LoggingInterceptor } from './logging/logging.interceptor';
import { HealthModule } from './health/health.module';
import { DatabaseModule } from './database/database.module';
import { AuthModule } from './auth/auth.module';
import { OpenBaoModule } from './openbao/openbao.module';
import { AgentsHttpModule } from './agents/agents-http.module';
import { AuthorizationModule } from './authorization/authorization.module';
import { TasksModule } from './tasks/tasks.module';
import { TasksHttpModule } from './tasks/tasks-http.module';
import { PolicyHttpModule } from './policy/policy-http.module';
import { TemporalModule } from './temporal/temporal.module';
import { ApprovalsHttpModule } from './approvals/approvals-http.module';
import { AuditModule } from './audit/audit.module';
import { AuditHttpModule } from './audit/audit-http.module';
import { AuditIndexerModule } from './audit/opensearch/audit-indexer.module';
import { LiveEventsHttpModule } from './audit/live/live-events-http.module';
import { EvidenceHttpModule } from './evidence/evidence-http.module';
import { KillSwitchesHttpModule } from './kill-switches/kill-switches-http.module';
import { RateLimitModule } from './rate-limit/rate-limit.module';
import { WebhooksHttpModule } from './webhooks/webhooks-http.module';
import { WebhookDeliveryConsumerModule } from './webhooks/webhook-delivery-consumer.module';
import { IdempotencyModule } from './idempotency/idempotency.module';

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
    AuthorizationModule,
    TasksModule,
    TasksHttpModule,
    PolicyHttpModule,
    TemporalModule,
    ApprovalsHttpModule,
    AuditHttpModule,
    AuditIndexerModule,
    LiveEventsHttpModule,
    EvidenceHttpModule,
    KillSwitchesHttpModule,
    RateLimitModule,
    WebhooksHttpModule,
    WebhookDeliveryConsumerModule,
    IdempotencyModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    { provide: APP_INTERCEPTOR, useClass: LoggingInterceptor },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(CorrelationIdMiddleware).forRoutes('*');
  }
}
