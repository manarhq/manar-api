import {
  CallHandler,
  ExecutionContext,
  Inject,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { WINSTON_MODULE_PROVIDER } from 'nest-winston';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { Logger } from 'winston';
import { Observable, tap } from 'rxjs';

/**
 * Logs one structured JSON line per completed request (method, path,
 * status code, duration). The correlation ID itself is attached by the
 * Winston format in `winston.config.ts`, which reads it from the
 * AsyncLocalStorage context `CorrelationIdMiddleware` establishes.
 */
@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  constructor(
    @Inject(WINSTON_MODULE_PROVIDER) private readonly logger: Logger,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const request = context.switchToHttp().getRequest<FastifyRequest>();
    const response = context.switchToHttp().getResponse<FastifyReply>();
    const startedAt = Date.now();

    return next.handle().pipe(
      tap({
        next: () => this.logCompletion(request, response, startedAt),
        error: () => this.logCompletion(request, response, startedAt),
      }),
    );
  }

  private logCompletion(
    request: FastifyRequest,
    response: FastifyReply,
    startedAt: number,
  ): void {
    this.logger.info('request completed', {
      method: request.method,
      url: request.url,
      statusCode: response.statusCode,
      durationMs: Date.now() - startedAt,
    });
  }
}
