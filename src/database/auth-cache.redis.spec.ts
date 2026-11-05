import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AuthCache } from './auth-cache.service';

const url = process.env.REDIS_URL;
describe.skipIf(!url)('AuthCache across replicas (redis)', () => {
  const config = { get: (k: string) => (k === 'REDIS_URL' ? url : undefined) };
  const a = new AuthCache(config as never);
  const b = new AuthCache(config as never);
  beforeAll(async () => {
    await a.onModuleInit();
    await b.onModuleInit();
  });
  afterAll(async () => {
    await a.onModuleDestroy();
    await b.onModuleDestroy();
  });

  it('an invalidation on replica A clears replica B within a moment', async () => {
    let roles = ['A', 'B'];
    const load = () => Promise.resolve(roles);
    expect(await b.remember('k', load)).toEqual(['A', 'B']);
    roles = ['A'];
    expect(await b.remember('k', load)).toEqual(['A', 'B']); // B still holds the old entry
    a.invalidate();
    const deadline = Date.now() + 2000;
    let seen: string[] = ['A', 'B'];
    while (Date.now() < deadline && seen.length !== 1) {
      await new Promise((r) => setTimeout(r, 25));
      seen = (await b.remember('k', load)) ?? [];
    }
    expect(seen).toEqual(['A']);
  });
});
