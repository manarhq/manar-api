import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthCache } from './auth-cache.service';

describe('AuthCache', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('serves a hit for 30 s, then loads again; null is never cached', async () => {
    const cache = new AuthCache();
    const load = vi.fn(() => Promise.resolve({ roles: ['A'] }));
    await cache.remember('k', load);
    await cache.remember('k', load);
    expect(load).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(AuthCache.TTL_MS + 1);
    await cache.remember('k', load);
    expect(load).toHaveBeenCalledTimes(2);

    const none = vi.fn(() => Promise.resolve(null));
    await cache.remember('n', none);
    await cache.remember('n', none);
    expect(none).toHaveBeenCalledTimes(2);
  });

  it('invalidate() takes effect at once, not after the TTL', async () => {
    const cache = new AuthCache();
    let roles = ['A', 'B'];
    const load = () => Promise.resolve(roles);
    expect(await cache.remember('k', load)).toEqual(['A', 'B']);
    roles = ['A']; // a role was revoked
    cache.invalidate();
    expect(await cache.remember('k', load)).toEqual(['A']);
  });

  it('a load that began before an invalidation is not stored (no re-poisoning)', async () => {
    const cache = new AuthCache();
    let release!: (v: string[]) => void;
    const slow = new Promise<string[]>((r) => (release = r));
    const inflight = cache.remember('k', () => slow); // read the old roles...
    cache.invalidate(); // ...a revoke commits meanwhile
    release(['OLD']);
    await inflight;
    const fresh = vi.fn(() => Promise.resolve(['NEW']));
    expect(await cache.remember('k', fresh)).toEqual(['NEW']);
    expect(fresh).toHaveBeenCalledTimes(1);
  });
});
