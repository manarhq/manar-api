import { Global, Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { WinstonModule } from 'nest-winston';
import { createWinstonOptions } from './winston.config';
import { CorrelationIdMiddleware } from './correlation-id.middleware';
import { LoggingInterceptor } from './logging.interceptor';
import type { AppConfig } from '../config/env.validation';

/**
 * Structured JSON logging (Winston) plus the correlation-ID plumbing
 * (`CorrelationIdMiddleware` for the request-scoped ID, `LoggingInterceptor`
 * for the per-request completion log line). Global so any module can inject
 * the Winston logger without re-importing this module.
 */
@Global()
@Module({
  imports: [
    WinstonModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService<AppConfig, true>) =>
        createWinstonOptions(configService.get('LOG_LEVEL', { infer: true })),
    }),
  ],
  providers: [CorrelationIdMiddleware, LoggingInterceptor],
  exports: [CorrelationIdMiddleware, LoggingInterceptor],
})
export class LoggingModule {}
