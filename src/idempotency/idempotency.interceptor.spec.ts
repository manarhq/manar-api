import { describe, expect, it } from 'vitest';
import { ConflictException, type ExecutionContext } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import { of, throwError, type Observable } from 'rxjs';
import type { AppConfig } from '../config/env.validation';
import { IdempotencyStoreService } from './idempotency-store.service';
import { IdempotencyInterceptor } from './idempotency.interceptor';

/** An in-memory stand-in for `IdempotencyStoreService`'s Redis-backed contract — same claim/cache/release semantics, no real Redis. */
function fakeStore(): IdempotencyStoreService {
  const values = new Map<string, unknown>();
  const inProgress = new Set<string>();
  return {
    claim: (key: string) => {
      if (values.has(key) || inProgress.has(key)) return Promise.resolve(false);
      inProgress.add(key);
      return Promise.resolve(true);
    },
    getCached: (key: string) => Promise.resolve(values.get(key)),
    store: (key: string, value: unknown) => {
      values.set(key, value);
      inProgress.delete(key);
      return Promise.resolve();
    },
    release: (key: string) => {
      inProgress.delete(key);
      values.delete(key);
      return Promise.resolve();
    },
  } as unknown as IdempotencyStoreService;
}

function fakeConfigService(): ConfigService<AppConfig, true> {
  return {
    get: () => 86_400_000,
  } as unknown as ConfigService<AppConfig, true>;
}

function fakeContext(headers: Record<string, string> = {}): ExecutionContext {
  const request = {
    headers,
    authContext: { tenant: { id: 'tenant-1' } },
  };
  return {
    switchToHttp: () => ({
      getRequest: () => request,
      getResponse: () => ({}),
    }),
    getClass: () => ({ name: 'TestController' }),
    getHandler: () => ({ name: 'testHandler' }),
  } as unknown as ExecutionContext;
}

function handlerReturning(value: unknown, callCount: { n: number }) {
  return {
    handle: (): Observable<unknown> => {
      callCount.n += 1;
      return of(value);
    },
  };
}

describe('IdempotencyInterceptor', () => {
  it('a request with no Idempotency-Key header passes straight through, untouched', async () => {
    const interceptor = new IdempotencyInterceptor(
      fakeStore(),
      fakeConfigService(),
    );
    const calls = { n: 0 };
    const result = await interceptor.intercept(
      fakeContext(),
      handlerReturning({ ok: true }, calls),
    );
    await expect(firstValue(result)).resolves.toEqual({ ok: true });
    expect(calls.n).toBe(1);
  });

  it('the first request with a given key executes the handler and caches the result', async () => {
    const store = fakeStore();
    const interceptor = new IdempotencyInterceptor(store, fakeConfigService());
    const calls = { n: 0 };
    const result = await interceptor.intercept(
      fakeContext({ 'idempotency-key': 'key-1' }),
      handlerReturning({ id: 'created-1' }, calls),
    );
    await expect(firstValue(result)).resolves.toEqual({ id: 'created-1' });
    expect(calls.n).toBe(1);
  });

  it('a replay with the SAME key returns the cached response WITHOUT re-executing the handler', async () => {
    const store = fakeStore();
    const interceptor = new IdempotencyInterceptor(store, fakeConfigService());
    const calls = { n: 0 };

    const first = await interceptor.intercept(
      fakeContext({ 'idempotency-key': 'key-1' }),
      handlerReturning({ id: 'created-1' }, calls),
    );
    await firstValue(first);
    expect(calls.n).toBe(1);

    // Second call with the same key -- the handler factory below would
    // return a DIFFERENT value if actually invoked, proving the cached
    // value (not a fresh execution) is what comes back.
    const second = await interceptor.intercept(
      fakeContext({ 'idempotency-key': 'key-1' }),
      handlerReturning({ id: 'created-2-should-never-be-seen' }, calls),
    );
    await expect(firstValue(second)).resolves.toEqual({ id: 'created-1' });
    expect(calls.n).toBe(1); // still 1 -- the second handler was never called
  });

  it('a DIFFERENT key executes the handler again (a genuinely new request)', async () => {
    const store = fakeStore();
    const interceptor = new IdempotencyInterceptor(store, fakeConfigService());
    const calls = { n: 0 };

    await firstValue(
      await interceptor.intercept(
        fakeContext({ 'idempotency-key': 'key-1' }),
        handlerReturning({ id: 'created-1' }, calls),
      ),
    );
    await expect(
      firstValue(
        await interceptor.intercept(
          fakeContext({ 'idempotency-key': 'key-2' }),
          handlerReturning({ id: 'created-2' }, calls),
        ),
      ),
    ).resolves.toEqual({ id: 'created-2' });
    expect(calls.n).toBe(2);
  });

  it('a concurrent duplicate (claimed but not yet cached) is rejected with 409, not silently dropped or blocked', async () => {
    const store = fakeStore();
    await store.claim(
      'manar:idempotency:tenant-1:TestController.testHandler:key-1',
      1000,
    );
    const interceptor = new IdempotencyInterceptor(store, fakeConfigService());
    await expect(
      interceptor.intercept(
        fakeContext({ 'idempotency-key': 'key-1' }),
        handlerReturning({ id: 'x' }, { n: 0 }),
      ),
    ).rejects.toBeInstanceOf(ConflictException);
  });

  it('a handler that throws releases the claim -- a retry with the same key is free to attempt again', async () => {
    const store = fakeStore();
    const interceptor = new IdempotencyInterceptor(store, fakeConfigService());
    const failingHandler = {
      handle: () => throwError(() => new Error('boom')),
    };

    await expect(
      interceptor.intercept(
        fakeContext({ 'idempotency-key': 'key-1' }),
        failingHandler,
      ),
    ).rejects.toThrow('boom');

    // A retry with the same key after the failure succeeds and actually
    // executes (not treated as a duplicate of the failed attempt).
    const calls = { n: 0 };
    const retried = await interceptor.intercept(
      fakeContext({ 'idempotency-key': 'key-1' }),
      handlerReturning({ id: 'succeeded-on-retry' }, calls),
    );
    await expect(firstValue(retried)).resolves.toEqual({
      id: 'succeeded-on-retry',
    });
    expect(calls.n).toBe(1);
  });

  it('scopes the same Idempotency-Key value separately per tenant', async () => {
    const store = fakeStore();
    const interceptor = new IdempotencyInterceptor(store, fakeConfigService());

    const tenantAContext = {
      switchToHttp: () => ({
        getRequest: () => ({
          headers: { 'idempotency-key': 'shared-key' },
          authContext: { tenant: { id: 'tenant-A' } },
        }),
        getResponse: () => ({}),
      }),
      getClass: () => ({ name: 'TestController' }),
      getHandler: () => ({ name: 'testHandler' }),
    } as unknown as ExecutionContext;
    const tenantBContext = {
      switchToHttp: () => ({
        getRequest: () => ({
          headers: { 'idempotency-key': 'shared-key' },
          authContext: { tenant: { id: 'tenant-B' } },
        }),
        getResponse: () => ({}),
      }),
      getClass: () => ({ name: 'TestController' }),
      getHandler: () => ({ name: 'testHandler' }),
    } as unknown as ExecutionContext;

    const calls = { n: 0 };
    await firstValue(
      await interceptor.intercept(
        tenantAContext,
        handlerReturning({ tenant: 'A' }, calls),
      ),
    );
    // Same literal key, different tenant -- must NOT be treated as a
    // duplicate of tenant A's request.
    await expect(
      firstValue(
        await interceptor.intercept(
          tenantBContext,
          handlerReturning({ tenant: 'B' }, calls),
        ),
      ),
    ).resolves.toEqual({ tenant: 'B' });
    expect(calls.n).toBe(2);
  });
});

function firstValue<T>(observable: Observable<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    observable.subscribe({ next: resolve, error: reject });
  });
}
