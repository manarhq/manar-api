import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { AppConfigModule } from '../config/config.module';
import { CorrelationIdMiddleware } from '../logging/correlation-id.middleware';
import { LoggingInterceptor } from '../logging/logging.interceptor';
import { LoggingModule } from '../logging/logging.module';
import { DatabaseModule } from '../database/database.module';
import { OpenBaoModule } from '../openbao/openbao.module';
import { AgentsModule } from '../agents/agents.module';
import { AuthorizationModule } from '../authorization/authorization.module';
import { AgentAuthorizeModule } from '../authorization/agent-authorize.module';
import { TasksModule } from '../tasks/tasks.module';
import { DelegationModule } from '../delegation/delegation.module';
import { ToolInvokeModule } from '../tools/tool-invoke.module';
import { TemporalModule } from '../temporal/temporal.module';
import { AgentApprovalsModule } from '../approvals/agent-approvals.module';
import { AgentWhoamiController } from './agent-whoami.controller';
import { AgentMtlsGuardModule } from './agent-mtls-guard.module';

/**
 * Root module for the *second*, agent-facing Nest application
 * (`/agent/v1/*`, mTLS — see `src/main.ts`'s two-listener bootstrap and
 * docs/agent-identity.md). A wholly separate `NestFactory.create()` call
 * from `AppModule`, because Fastify/Node's `https` server options
 * (`requestCert`/`rejectUnauthorized`/`ca`) are per-listener, and this
 * listener's TLS posture (mandatory client-cert mTLS) must never apply to
 * the human-facing HTTP listener or vice versa. Each `NestFactory.create()`
 * call gets its own DI container, so `@Global()` modules like
 * `DatabaseModule`/`LoggingModule`/`AuthorizationModule` need importing
 * here explicitly too — "global" only means "global within one
 * application's module graph."
 *
 * Phase 5 adds the real endpoints under `/agent/v1/*` this listener was
 * built for (`AgentWhoamiController` was Phase 4's placeholder proving the
 * mTLS plumbing worked end-to-end): `AgentAuthorizeModule`
 * (`POST /agent/v1/authorize`) and `DelegationModule`
 * (`POST /agent/v1/tasks/:id/delegate`). `AgentsModule`/`TasksModule` here
 * are the *services-only* modules (no controllers — see their own doc
 * comments) so this listener never exposes the JWT-gated `/agents` or
 * `/tasks` human-facing routes, which would be structurally unreachable
 * here anyway (`rejectUnauthorized: true` on this listener refuses any
 * connection without a client certificate before Nest ever routes a
 * request) quite apart from being the wrong surface for them. Phase 7b
 * adds `ToolInvokeModule` (`POST /agent/v1/tools/invoke`) — the first
 * endpoint on this listener that actually executes something, on top of
 * this exact same unchanged `AuthorizationService` pipeline. Phase 8 adds
 * `TemporalModule` (starts/signals `ApprovalWorkflow` — see
 * docs/approvals.md) and `AgentApprovalsModule`
 * (`GET /agent/v1/approvals/:id`, the endpoint an agent polls after a
 * `PENDING_APPROVAL` response).
 */
@Module({
  imports: [
    AppConfigModule,
    LoggingModule,
    DatabaseModule,
    OpenBaoModule,
    AgentMtlsGuardModule,
    AgentsModule,
    AuthorizationModule,
    TasksModule,
    AgentAuthorizeModule,
    DelegationModule,
    ToolInvokeModule,
    TemporalModule,
    AgentApprovalsModule,
  ],
  controllers: [AgentWhoamiController],
  providers: [{ provide: APP_INTERCEPTOR, useClass: LoggingInterceptor }],
})
export class AgentMtlsAppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(CorrelationIdMiddleware).forRoutes('*');
  }
}
