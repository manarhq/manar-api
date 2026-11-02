import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Logger } from 'winston';
import { Observable, tap } from 'rxjs';
import { CORRELATION_ID_HEADER } from './correlation-id.store';

/** Error class and code a handler threw, keyed by the raw request; read by the onResponse log. */
const handlerErrors = new WeakMap<
  object,
  { errorName: string; errorCode?: string }
>();

/**
 * Remembers the class and code of an error a handler threw, so the access log line written in
 * `onResponse` can say what failed. It does not log: inside the interceptor the exception filter
 * has not run yet, so the reply still carries the route's default status (200/201).
 */
@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const request = context.switchToHttp().getRequest<FastifyRequest>();
    return next.handle().pipe(
      tap({
        error: (err: unknown) => {
          const e = err as { name?: unknown; code?: unknown } | null;
          handlerErrors.set(request.raw, {
            errorName:
              (err as object | null)?.constructor?.name ??
              (typeof e?.name === 'string' ? e.name : 'Error'),
            ...(typeof e?.code === 'string' ? { errorCode: e.code } : {}),
          });
        },
      }),
    );
  }
}

/**
 * One structured line per finished request, from Fastify's `onResponse` hook, where
 * `reply.statusCode` is final. That covers guard rejections, unknown routes and exception-filter
 * statuses, which an interceptor never sees correctly. The path is the route template
 * (`/i/:code`), never the raw URL, so ids, query strings and credentials in paths stay out of logs.
 */
export function logRequests(fastify: FastifyInstance, logger: Logger): void {
  fastify.addHook('onResponse', (request, reply, done) => {
    const correlationId = reply.getHeader(CORRELATION_ID_HEADER);
    logger.info('request completed', {
      method: request.method,
      route: request.routeOptions.url ?? 'unmatched',
      statusCode: reply.statusCode,
      durationMs: Math.round(reply.elapsedTime),
      ...(typeof correlationId === 'string' ? { correlationId } : {}),
      ...handlerErrors.get(request.raw),
    });
    done();
  });
}
