import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { Injectable, NestMiddleware } from '@nestjs/common';
import {
  CORRELATION_ID_HEADER,
  correlationIdStore,
} from './correlation-id.store';

/**
 * Reads `x-correlation-id` off the incoming request (generating one if it's
 * absent), echoes it back on the response, and runs the rest of the
 * request's async chain inside an AsyncLocalStorage context so every log
 * line emitted while handling this request can pick it up.
 *
 * Registered as global Nest middleware in `AppModule`. Under the Fastify
 * adapter, Nest middleware receives the raw Node `req`/`res` objects (not
 * Fastify's wrappers) — see the official Fastify adapter docs.
 */
@Injectable()
export class CorrelationIdMiddleware implements NestMiddleware<
  IncomingMessage,
  ServerResponse
> {
  use(req: IncomingMessage, res: ServerResponse, next: () => void): void {
    const headerValue = req.headers[CORRELATION_ID_HEADER];
    const correlationId =
      (Array.isArray(headerValue) ? headerValue[0] : headerValue) ??
      randomUUID();

    res.setHeader(CORRELATION_ID_HEADER, correlationId);

    correlationIdStore.run({ correlationId }, next);
  }
}
