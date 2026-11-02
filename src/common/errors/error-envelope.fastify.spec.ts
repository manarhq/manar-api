import { Controller, Get, NotFoundException } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import {
  FastifyAdapter,
  type NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { Test } from '@nestjs/testing';
import { WINSTON_MODULE_PROVIDER } from 'nest-winston';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ErrorEnvelopeFilter } from './error-envelope.filter';
import { ERROR_REFERENCE_PATTERN } from './error-reference';

@Controller('t')
class ThrowingController {
  @Get('boom')
  boom(): never {
    throw new Error('connection string postgres://user:pw@db/x refused');
  }

  @Get('gone')
  gone(): never {
    throw new NotFoundException('This device was already removed.');
  }
}

describe('ErrorEnvelopeFilter on a real Fastify app', () => {
  let app: NestFastifyApplication;
  const logger = { error: vi.fn(), warn: vi.fn(), info: vi.fn() };

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      controllers: [ThrowingController],
      providers: [
        { provide: WINSTON_MODULE_PROVIDER, useValue: logger },
        { provide: APP_FILTER, useClass: ErrorEnvelopeFilter },
      ],
    }).compile();
    app = moduleRef.createNestApplication<NestFastifyApplication>(
      new FastifyAdapter(),
      { logger: false },
    );
    await app.init();
    await app.getHttpAdapter().getInstance().ready();
  });
  afterAll(() => app.close());

  it('never sends internal text to the caller', async () => {
    const res = await app.inject({ method: 'GET', url: '/t/boom' });
    expect(res.statusCode).toBe(500);
    expect(res.body).not.toMatch(/postgres|pw|stack/);
    const body = res.json<{ reference: string; message: string }>();
    expect(body.reference).toMatch(ERROR_REFERENCE_PATTERN);
    expect(body.message).toMatch(/Nothing was changed/);
  });

  it('keeps a known message', async () => {
    const res = await app.inject({ method: 'GET', url: '/t/gone' });
    expect(res.statusCode).toBe(404);
    expect(res.json()).toMatchObject({
      message: 'This device was already removed.',
    });
  });

  it('answers an unknown route with plain words', async () => {
    const res = await app.inject({ method: 'GET', url: '/nope' });
    expect(res.statusCode).toBe(404);
    expect(res.json<{ message: string }>().message).toMatch(/couldn't find/);
  });
});
