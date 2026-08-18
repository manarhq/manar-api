import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { AppConfigModule } from '../config/config.module';
import { CorrelationIdMiddleware } from '../logging/correlation-id.middleware';
import { LoggingInterceptor } from '../logging/logging.interceptor';
import { LoggingModule } from '../logging/logging.module';
import { DatabaseModule } from '../database/database.module';
import { AgentWhoamiController } from './agent-whoami.controller';
import { AgentMtlsGuard } from './agent-mtls.guard';

/**
 * Root module for the *second*, agent-facing Nest application
 * (`/agent/v1/*`, mTLS — see `src/main.ts`'s two-listener bootstrap and
 * docs/agent-identity.md). A wholly separate `NestFactory.create()` call
 * from `AppModule`, because Fastify/Node's `https` server options
 * (`requestCert`/`rejectUnauthorized`/`ca`) are per-listener, and this
 * listener's TLS posture (mandatory client-cert mTLS) must never apply to
 * the human-facing HTTP listener or vice versa. Each `NestFactory.create()`
 * call gets its own DI container, so `@Global()` modules like
 * `DatabaseModule`/`LoggingModule` need importing here explicitly too —
 * "global" only means "global within one application's module graph."
 */
@Module({
  imports: [AppConfigModule, LoggingModule, DatabaseModule],
  controllers: [AgentWhoamiController],
  providers: [
    AgentMtlsGuard,
    { provide: APP_INTERCEPTOR, useClass: LoggingInterceptor },
  ],
})
export class AgentMtlsAppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(CorrelationIdMiddleware).forRoutes('*');
  }
}
