import {
  CanActivate,
  Controller,
  Delete,
  ForbiddenException,
  Get,
  NotFoundException,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import {
  FastifyAdapter,
  type NestFastifyApplication,
} from '@nestjs/platform-fastify';
import type { Logger } from 'winston';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { LoggingInterceptor, logRequests } from './logging.interceptor';

class Deny implements CanActivate {
  canActivate(): boolean {
    throw new ForbiddenException();
  }
}

class FakePrismaError extends Error {
  code = 'P2003';
}

@Controller()
class TestController {
  @Delete('hosts/:id')
  remove(): void {
    throw new FakePrismaError('foreign key');
  }

  @Post('events')
  events(): void {
    throw new NotFoundException();
  }

  @Get('i/:code')
  install(@Param('code') code: string): string {
    return code;
  }

  @Get('guarded')
  @UseGuards(Deny)
  guarded(): string {
    return 'never';
  }
}

describe('request log', () => {
  const lines: Record<string, unknown>[] = [];
  const logger = {
    info: (_msg: string, meta: Record<string, unknown>) => lines.push(meta),
  } as unknown as Logger;
  let app: NestFastifyApplication;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      controllers: [TestController],
      providers: [{ provide: APP_INTERCEPTOR, useClass: LoggingInterceptor }],
    }).compile();
    app = moduleRef.createNestApplication(new FastifyAdapter(), {
      logger: false,
    });
    logRequests(app.getHttpAdapter().getInstance(), logger);
    await app.init();
    await app.getHttpAdapter().getInstance().ready();
  });

  afterAll(() => app.close());

  async function call(method: 'GET' | 'POST' | 'DELETE', url: string) {
    lines.length = 0;
    const res = await app.inject({ method, url });
    return { status: res.statusCode, line: lines[0] };
  }

  it('logs the status the client got when a handler throws', async () => {
    const { status, line } = await call('DELETE', '/hosts/abc');
    expect(status).toBe(500);
    expect(line).toMatchObject({
      method: 'DELETE',
      route: '/hosts/:id',
      statusCode: 500,
      errorName: 'FakePrismaError',
      errorCode: 'P2003',
    });

    const notFound = await call('POST', '/events');
    expect(notFound.line).toMatchObject({ statusCode: 404 });
  });

  it('logs guard rejections and unknown routes', async () => {
    expect((await call('GET', '/guarded')).line).toMatchObject({
      statusCode: 403,
    });
    expect((await call('GET', '/nope?x=1')).line).toMatchObject({
      statusCode: 404,
      route: 'unmatched',
    });
  });

  it('logs the route template, never the raw path', async () => {
    const { status, line } = await call('GET', '/i/SECRETCODE.sh?t=1');
    expect(status).toBe(200);
    expect(line).toMatchObject({ route: '/i/:code', statusCode: 200 });
    expect(JSON.stringify(line)).not.toContain('SECRETCODE');
  });
});
