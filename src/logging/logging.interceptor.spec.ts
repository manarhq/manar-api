import { NotFoundException } from '@nestjs/common';
import type { CallHandler, ExecutionContext } from '@nestjs/common';
import { lastValueFrom, of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { LoggingInterceptor } from './logging.interceptor';

function run(handle: CallHandler['handle']) {
  const info = vi.fn();
  const context = {
    switchToHttp: () => ({
      getRequest: () => ({ method: 'DELETE', url: '/hosts/x' }),
      // The reply still says 200 when the handler throws: the filter sets it later.
      getResponse: () => ({ statusCode: 200 }),
    }),
  } as unknown as ExecutionContext;
  const done = lastValueFrom(
    new LoggingInterceptor({ info } as never).intercept(context, { handle }),
  ).catch(() => undefined);
  return done.then(() => info.mock.calls[0]?.[1] as { statusCode: number });
}

describe('LoggingInterceptor', () => {
  it('logs the status of a thrown error, not the reply default', async () => {
    expect(
      (await run(() => throwError(() => new NotFoundException()))).statusCode,
    ).toBe(404);
    expect(
      (await run(() => throwError(() => new Error('db')))).statusCode,
    ).toBe(500);
    expect((await run(() => of({ ok: true }))).statusCode).toBe(200);
  });
});
