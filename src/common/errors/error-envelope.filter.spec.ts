import {
  ArgumentsHost,
  BadRequestException,
  ConflictException,
  HttpException,
  HttpStatus,
  NotFoundException,
} from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import type { Logger } from 'winston';
import { parseBodyOrThrow } from '../../agents/parse-body.util';
import { correlationIdStore } from '../../logging/correlation-id.store';
import {
  ErrorEnvelopeFilter,
  type ErrorEnvelope,
} from './error-envelope.filter';
import { ERROR_REFERENCE_PATTERN, newErrorReference } from './error-reference';

function run(exception: unknown, method = 'POST', headersSent = false) {
  const logger = { error: vi.fn(), warn: vi.fn() };
  const sent: { status?: number; body?: ErrorEnvelope } = {};
  const reply = {
    sent: headersSent,
    raw: { headersSent, end: vi.fn() },
    status(code: number) {
      sent.status = code;
      return this;
    },
    header() {
      return this;
    },
    send(body: ErrorEnvelope) {
      sent.body = body;
    },
  };
  const host = {
    getType: () => 'http',
    switchToHttp: () => ({
      getRequest: () => ({ method, url: '/hosts/1?token=secret', id: 'req-1' }),
      getResponse: () => reply,
    }),
  } as unknown as ArgumentsHost;
  const filter = new ErrorEnvelopeFilter(logger as unknown as Logger);
  correlationIdStore.run({ correlationId: 'corr-1' }, () =>
    filter.catch(exception, host),
  );
  return { ...sent, logger, reply };
}

describe('newErrorReference', () => {
  it('is short, readable and differs per call', () => {
    const refs = new Set(Array.from({ length: 1000 }, newErrorReference));
    expect(refs.size).toBe(1000);
    for (const r of refs) expect(r).toMatch(ERROR_REFERENCE_PATTERN);
  });
});

describe('ErrorEnvelopeFilter', () => {
  it('keeps a known message and adds the reference and correlation id', () => {
    const { status, body, logger } = run(
      new ConflictException('Already decided by Ali.'),
    );
    expect(status).toBe(409);
    expect(body).toMatchObject({
      statusCode: 409,
      error: 'Conflict',
      message: 'Already decided by Ali.',
      correlationId: 'corr-1',
    });
    expect(body?.reference).toMatch(ERROR_REFERENCE_PATTERN);
    expect(logger.warn).toHaveBeenCalledWith(
      'request rejected',
      expect.objectContaining({ reference: body?.reference, path: '/hosts/1' }),
    );
  });

  it('replaces a bare status text with plain words', () => {
    expect(run(new NotFoundException()).body?.message).toMatch(/couldn't find/);
    expect(
      run(new NotFoundException('Cannot GET /nope')).body?.message,
    ).toMatch(/couldn't find/);
  });

  it('keeps extra fields of an object body', () => {
    const { body } = run(
      new HttpException(
        { decision: 'DENY', reason: 'llm_budget_exhausted' },
        HttpStatus.TOO_MANY_REQUESTS,
      ),
    );
    expect(body).toMatchObject({
      decision: 'DENY',
      reason: 'llm_budget_exhausted',
      statusCode: 429,
    });
    expect(body?.message).toMatch(/Too many attempts/);
  });

  it('hides an unknown error behind the generic message and logs the details', () => {
    const prismaLike = Object.assign(
      new Error('update or delete on table "hosts" violates foreign key'),
      { code: 'P2003' },
    );
    const { status, body, logger } = run(prismaLike, 'DELETE');
    expect(status).toBe(500);
    expect(body?.message).toMatch(/Something went wrong on our side/);
    expect(JSON.stringify(body)).not.toMatch(/hosts|foreign|P2003|stack/);
    const [line, fields] = logger.error.mock.calls[0] as [
      string,
      Record<string, unknown>,
    ];
    expect(line).toBe('request failed');
    expect(fields).toMatchObject({
      reference: body?.reference,
      errorCode: 'P2003',
    });
    expect(fields.errorMessage).toContain('foreign key');
    expect(typeof fields.stack).toBe('string');
  });

  it('says nothing changed when a read fails', () => {
    expect(run(new Error('boom'), 'GET').body?.message).toMatch(
      /Nothing was changed/,
    );
  });

  it.each([
    ['pool wait expired', new Error('timeout exceeded when trying to connect')],
    ['client query timeout', new Error('Query read timeout')],
    [
      'too many clients (53300)',
      Object.assign(new Error('sorry, too many clients already'), {
        code: '53300',
      }),
    ],
    [
      'too many clients behind Prisma',
      Object.assign(new Error('Raw query failed'), {
        code: 'P2010',
        meta: { driverAdapterError: { cause: { originalCode: '53300' } } },
      }),
    ],
    [
      'statement timeout (57014)',
      Object.assign(new Error('Raw query failed'), {
        code: 'P2010',
        meta: { driverAdapterError: { cause: { originalCode: '57014' } } },
      }),
    ],
    [
      'transaction start timeout (P2028)',
      Object.assign(
        new Error('Unable to start a transaction in the given time'),
        {
          code: 'P2028',
        },
      ),
    ],
  ])(
    'answers 503 enforcement_dependency_unavailable for %s',
    (_name, error) => {
      const r = run(error, 'GET');
      expect(r.status).toBe(503);
      expect(r.body).toMatchObject({
        reason: 'enforcement_dependency_unavailable',
        dependency: 'database',
      });
      expect(JSON.stringify(r.body)).not.toMatch(/5\d{4}|P20/);
    },
  );

  it('maps a duplicate and a missing row to 409 and 404', () => {
    expect(run(Object.assign(new Error('x'), { code: 'P2002' })).status).toBe(
      409,
    );
    expect(run(Object.assign(new Error('x'), { code: 'P2025' })).status).toBe(
      404,
    );
  });

  it("answers Fastify's own 4xx errors with plain words", () => {
    const { status, body } = run(
      Object.assign(new Error('Unsupported Media Type: text/plain'), {
        statusCode: 415,
      }),
    );
    expect(status).toBe(415);
    expect(body?.message).not.toMatch(/text\/plain/);
  });

  it('closes a stream that already sent its headers instead of answering', () => {
    const { body, reply } = run(new Error('mid-stream'), 'GET', true);
    expect(body).toBeUndefined();
    expect(reply.raw.end).toHaveBeenCalled();
  });

  it('phrases validation errors per field', () => {
    let thrown: unknown;
    try {
      parseBodyOrThrow(
        z.object({
          name: z.string().min(1),
          email: z.email(),
          role: z.enum(['admin', 'member']),
          age: z.number(),
        }),
        { name: '', email: 'nope', age: 'x' },
      );
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(BadRequestException);
    const { status, body } = run(thrown);
    expect(status).toBe(400);
    expect(body?.message).toBe(
      'Some details need fixing: name must not be empty; email must be a valid email address; role is required; age must be a number.',
    );
    expect(body?.fields).toEqual([
      { field: 'name', message: 'must not be empty' },
      { field: 'email', message: 'must be a valid email address' },
      { field: 'role', message: 'is required' },
      { field: 'age', message: 'must be a number' },
    ]);
  });
});
