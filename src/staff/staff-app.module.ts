import {
  type MiddlewareConsumer,
  Module,
  type NestModule,
} from '@nestjs/common';
import { APP_FILTER, APP_INTERCEPTOR } from '@nestjs/core';
import { AuditModule } from '../audit/audit.module';
import { JwksCacheService } from '../auth/jwks-cache.service';
import { ErrorEnvelopeFilter } from '../common/errors/error-envelope.filter';
import { AppConfigModule } from '../config/config.module';
import { DatabaseModule } from '../database/database.module';
import { LoggingModule } from '../logging/logging.module';
import { CorrelationIdMiddleware } from '../logging/correlation-id.middleware';
import { StaffAuthGuard } from './auth/staff-auth.guard';
import { StaffPermissionGuard } from './auth/staff-permission.guard';
import {
  ERROR_REFERENCE_SINK,
  ErrorReferenceRecorder,
} from './errors/error-reference.recorder';
import { StaffAuditInterceptor } from './http/staff-audit.interceptor';
import { StaffMeController } from './http/staff-me.controller';
import {
  StaffInvitesController,
  StaffInvitesService,
} from './auth/staff-invites';
import { StaffCoreModule } from './staff-core.module';
import { StaffIndexController } from './http/staff-index.controller';
import { StaffIndexService } from './index/staff-index.service';
import { StaffRecordsService } from './index/staff-records.service';
import { TrustLogService } from './trust-log.service';
import { StripeGateway } from '../billing/stripe.gateway';
import { KeycloakAdminClient } from '../keycloak/keycloak-admin.client';
import { StaffJobsService } from './staff-jobs.service';

/**
 * The staff listener's whole application (DESK spec §5, AC-6): its own Fastify app on STAFF_PORT,
 * holding only the staff module. No ingress routes it; a NetworkPolicy admits only DESK pods.
 */
@Module({
  imports: [
    AppConfigModule,
    LoggingModule,
    DatabaseModule,
    AuditModule,
    StaffCoreModule,
  ],
  controllers: [
    StaffMeController,
    StaffInvitesController,
    StaffIndexController,
  ],
  providers: [
    JwksCacheService,
    StaffAuthGuard,
    StaffPermissionGuard,
    StaffJobsService,
    StaffInvitesService,
    StaffIndexService,
    StaffRecordsService,
    TrustLogService,
    StripeGateway,
    KeycloakAdminClient,
    ErrorReferenceRecorder,
    { provide: ERROR_REFERENCE_SINK, useExisting: ErrorReferenceRecorder },
    { provide: APP_FILTER, useClass: ErrorEnvelopeFilter },
    { provide: APP_INTERCEPTOR, useClass: StaffAuditInterceptor },
  ],
})
export class StaffAppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(CorrelationIdMiddleware).forRoutes('*');
  }
}
