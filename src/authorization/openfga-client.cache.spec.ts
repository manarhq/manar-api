import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { OpenFgaClientService } from './openfga-client.service';

/** Spec 7.2: OpenFGA allow results are cached for a few seconds; nothing else is. */
const TTL = 3000;
const TUPLE = {
  user: 'agent:t1_a1',
  relation: 'can_use',
  object: 'grant:t1_g1',
};

function setup(ttl: number | undefined = TTL) {
  const calls = { check: 0, write: 0 };
  const fga = { allowed: true, down: false };
  const client = {
    check: vi.fn(() => {
      calls.check += 1;
      return fga.down
        ? Promise.reject(new Error('openfga down'))
        : Promise.resolve({ allowed: fga.allowed });
    }),
    write: vi.fn(() => {
      calls.write += 1;
      return Promise.resolve({});
    }),
  };
  const config = {
    get: (key: string) =>
      key === 'OPENFGA_CACHE_TTL_MS'
        ? ttl
        : key === 'OPENFGA_CHECK_TIMEOUT_MS'
          ? 500
          : undefined,
  } as unknown as ConfigService<AppConfig, true>;
  const service = new OpenFgaClientService(config);
  Object.assign(service, {
    client,
    checkClient: client,
    _storeId: 's',
    _authorizationModelId: 'm',
  });
  return { service, calls, fga };
}

describe('OpenFgaClientService allow cache (spec 7.2)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-10-28T10:00:00Z'));
  });
  afterEach(() => vi.useRealTimers());

  it('a second allow inside the TTL makes no OpenFGA call', async () => {
    const { service, calls } = setup();
    expect(await service.check(TUPLE)).toBe(true);
    expect(await service.check(TUPLE)).toBe(true);
    expect(calls.check).toBe(1);
  });

  it('after the TTL it asks OpenFGA again, and a revoked tuple is now denied', async () => {
    const { service, calls, fga } = setup();
    await service.check(TUPLE);
    fga.allowed = false; // revoked on another replica: no local write
    vi.advanceTimersByTime(TTL);
    expect(await service.check(TUPLE)).toBe(true); // still inside the bound
    vi.advanceTimersByTime(1);
    expect(await service.check(TUPLE)).toBe(false);
    expect(calls.check).toBe(2);
  });

  it('cache expired and OpenFGA unreachable: throws, so the pipeline denies', async () => {
    const { service, fga } = setup();
    await service.check(TUPLE);
    fga.down = true;
    vi.advanceTimersByTime(TTL + 1);
    await expect(service.check(TUPLE)).rejects.toThrow('openfga down');
  });

  it('denies and errors are never cached', async () => {
    const { service, calls, fga } = setup();
    fga.allowed = false;
    await service.check(TUPLE);
    fga.allowed = true;
    expect(await service.check(TUPLE)).toBe(true); // a fresh grant is seen at once
    fga.down = true;
    vi.advanceTimersByTime(TTL + 1);
    await expect(service.check(TUPLE)).rejects.toThrow();
    fga.down = false;
    await service.check(TUPLE);
    expect(calls.check).toBe(4);
  });

  it('a tuple delete through this process clears the cache at once', async () => {
    const { service, fga } = setup();
    await service.check(TUPLE);
    fga.allowed = false;
    await service.write({ deletes: [TUPLE] });
    expect(await service.check(TUPLE)).toBe(false);
  });

  it('consistency high bypasses the cache and does not read it', async () => {
    const { service, calls, fga } = setup();
    await service.check(TUPLE);
    fga.allowed = false;
    expect(await service.check(TUPLE, { consistency: 'high' })).toBe(false);
    expect(calls.check).toBe(2);
  });

  it('entries are per full tuple: another tenant never shares one', async () => {
    const { service, calls } = setup();
    await service.check(TUPLE);
    await service.check({ ...TUPLE, object: 'grant:t2_g1' });
    expect(calls.check).toBe(2);
  });

  it('TTL 0 turns the cache off', async () => {
    const { service, calls } = setup(0);
    await service.check(TUPLE);
    await service.check(TUPLE);
    expect(calls.check).toBe(2);
  });

  it('a check with a condition context is never cached and passes the context through', async () => {
    const { service, calls } = setup();
    const context = { current_time: '2026-10-28T10:00:00Z' };
    expect(await service.check(TUPLE, { context })).toBe(true);
    expect(await service.check(TUPLE, { context })).toBe(true);
    expect(calls.check).toBe(2);
    const client = (
      service as unknown as {
        client: { check: { mock: { calls: unknown[][] } } };
      }
    ).client;
    expect(client.check.mock.calls[0]![0]).toMatchObject({ context });
  });
});
