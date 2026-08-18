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

@Module({
  imports: [
    AppConfigModule,
    LoggingModule,
    HealthModule,
    DatabaseModule,
    AuthModule,
    OpenBaoModule,
    AgentsHttpModule,
    AuthorizationModule,
    TasksModule,
    TasksHttpModule,
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
