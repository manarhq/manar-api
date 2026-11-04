import { STATUS_CODES } from 'node:http';
import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  Inject,
  Optional,
} from '@nestjs/common';
import { WINSTON_MODULE_PROVIDER } from 'nest-winston';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { Logger } from 'winston';
import { getCorrelationId } from '../../logging/correlation-id.store';
import { newErrorReference } from './error-reference';
import {
  ERROR_REFERENCE_SINK,
  type ErrorReferenceSink,
} from '../../staff/errors/error-reference.recorder';

/**
 * The body of every error response, on both listeners. `statusCode`, `error` and `message` keep
 * Nest's default shape so existing clients still parse it; `reference` and `correlationId` are new.
 * An `HttpException` thrown with an object body keeps its extra fields (`reason`, `fields`, ...).
 */
export interface ErrorEnvelope {
  statusCode: number;
  error: string;
  /** Plain words for a person: what happened and what to do. Never a stack, query or driver text. */
  message: string;
  /** `MNR-XXXXXX`, unique per occurrence; the log line with the full details carries the same value. */
  reference: string;
  correlationId?: string;
  [extra: string]: unknown;
}

const BAD_REQUEST =
  "We couldn't process this request. Check the details and try again.";
const NOT_FOUND =
  "We couldn't find what you were looking for. It may have been removed.";

/** Shown in place of Nest's and Fastify's bare status texts ("Not Found", "Cannot GET /x"). */
export const HUMAN_DEFAULTS: Partial<Record<number, string>> = {
  400: BAD_REQUEST,
  401: 'Your session has ended. Sign in again to continue.',
  403: "You don't have permission to do this. Ask a workspace admin if you need access.",
  404: NOT_FOUND,
  405: "This action isn't available here.",
  409: 'Someone else changed this at the same time. Refresh the page and try again.',
  410: 'This link or item has expired.',
  413: 'This is too large to send. Try a smaller file or fewer items.',
  415: "This request format isn't supported.",
  422: "We couldn't process these details. Check them and try again.",
  429: 'Too many attempts. Wait a moment and try again.',
  503: 'This service is briefly unavailable. Nothing was changed. Try again in a minute.',
};

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function genericServerMessage(method: string): string {
  return SAFE_METHODS.has(method)
    ? "Something went wrong on our side and we couldn't load this. Nothing was changed. Try again, or contact support with the reference code."
    : "Something went wrong on our side and we couldn't finish this. Refresh to check whether your change was saved before trying again, or contact support with the reference code.";
}

function humanDefault(status: number, method: string): string {
  return (
    HUMAN_DEFAULTS[status] ??
    (status >= 500 ? genericServerMessage(method) : BAD_REQUEST)
  );
}

/** Nest's and Fastify's own wording, which says nothing a person can act on. */
function isBareStatusText(message: string, status: number): boolean {
  return (
    message === STATUS_CODES[status] ||
    message === `${STATUS_CODES[status]} Exception` ||
    /^Cannot (GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) \//.test(message) ||
    /^ThrottlerException/.test(message)
  );
}

/** Prisma errors that are really the caller's: a duplicate or a row that is gone. */
const PRISMA_CLIENT_ERRORS: Record<
  string,
  { status: number; message: string }
> = {
  P2002: {
    status: 409,
    message: 'This already exists. Use a different name or value.',
  },
  P2025: { status: 404, message: NOT_FOUND },
};

interface Classified {
  status: number;
  body: Record<string, unknown>;
  /** Unknown to us: the person sees the generic text, the log keeps everything. */
  unexpected: boolean;
}

function classify(exception: unknown, method: string): Classified {
  if (exception instanceof HttpException) {
    const status = exception.getStatus();
    const response = exception.getResponse();
    const body: Record<string, unknown> =
      typeof response === 'string' ? { message: response } : { ...response };
    let message = Array.isArray(body.message)
      ? body.message.join('. ')
      : typeof body.message === 'string'
        ? body.message
        : '';
    if (!message || isBareStatusText(message, status)) {
      message = humanDefault(status, method);
    }
    return { status, body: { ...body, message }, unexpected: false };
  }

  const code = (exception as { code?: unknown } | null)?.code;
  if (typeof code === 'string' && PRISMA_CLIENT_ERRORS[code]) {
    const { status, message } = PRISMA_CLIENT_ERRORS[code];
    return { status, body: { message }, unexpected: false };
  }

  // Fastify's own errors (body parser, media type, payload size) carry a 4xx statusCode.
  const statusCode = (exception as { statusCode?: unknown } | null)?.statusCode;
  if (typeof statusCode === 'number' && statusCode >= 400 && statusCode < 500) {
    return {
      status: statusCode,
      body: { message: humanDefault(statusCode, method) },
      unexpected: false,
    };
  }

  return {
    status: 500,
    body: { message: genericServerMessage(method) },
    unexpected: true,
  };
}

/** Request path without the query string, which can carry tokens. */
function pathOf(url: string): string {
  const q = url.indexOf('?');
  return q === -1 ? url : url.slice(0, q);
}

/**
 * One error envelope for the whole API (registered as `APP_FILTER` on the human and the agent
 * listener). Every error gets a fresh reference code, logged with the correlation id so support
 * can find the occurrence; a 5xx logs the full error and returns only the generic message.
 */
@Catch()
export class ErrorEnvelopeFilter implements ExceptionFilter {
  constructor(
    @Inject(WINSTON_MODULE_PROVIDER) private readonly logger: Logger,
    @Optional()
    @Inject(ERROR_REFERENCE_SINK)
    private readonly references?: ErrorReferenceSink,
  ) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    if (host.getType() !== 'http') throw exception;
    const http = host.switchToHttp();
    const request = http.getRequest<FastifyRequest>();
    const reply = http.getResponse<FastifyReply>();
    const method = request?.method ?? 'GET';

    const { status, body, unexpected } = classify(exception, method);
    const reference = newErrorReference();
    const correlationId = getCorrelationId() ?? request?.id;
    const envelope: ErrorEnvelope = {
      ...body,
      statusCode: status,
      error:
        typeof body.error === 'string'
          ? body.error
          : (STATUS_CODES[status] ?? 'Error'),
      message: body.message as string,
      reference,
      correlationId,
    };

    const logFields = {
      reference,
      statusCode: status,
      method,
      path: pathOf(request?.url ?? ''),
    };
    if (unexpected || status >= 500) {
      const err = exception instanceof Error ? exception : undefined;
      this.logger.error('request failed', {
        ...logFields,
        errorName: err?.name,
        errorMessage: err?.message ?? String(exception),
        errorCode: (exception as { code?: unknown } | null)?.code,
        stack: err?.stack,
      });
    } else {
      this.logger.warn('request rejected', {
        ...logFields,
        userMessage: envelope.message,
      });
    }

    if (request)
      this.references?.record({
        reference,
        status,
        code: typeof body.code === 'string' ? body.code : undefined,
        correlationId,
        request,
      });

    // A stream (SSE) that already sent its headers can only be closed, not answered.
    if (reply.sent || reply.raw?.headersSent) {
      reply.raw?.end?.();
      return;
    }
    void reply
      .status(status)
      .header('content-type', 'application/json; charset=utf-8')
      .send(envelope);
  }
}
