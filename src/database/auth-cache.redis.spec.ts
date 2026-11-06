import { createServer, connect, type Server, type Socket } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { AuthCache } from './auth-cache.service';

const url = process.env.REDIS_URL;
const redis = url ? new URL(url) : null;
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** A TCP proxy to Redis that the test can kill and restart on the same port. */
class Proxy {
  private server?: Server;
  private sockets = new Set<Socket>();
  constructor(readonly port: number) {}
  start(): Promise<void> {
    this.server = createServer((client) => {
      const upstream = connect(Number(redis!.port || 6379), redis!.hostname);
      for (const s of [client, upstream]) {
        this.sockets.add(s);
        s.on('close', () => this.sockets.delete(s));
        s.on('error', () => undefined);
      }
      client.pipe(upstream).pipe(client);
    });
    return new Promise((r) => this.server!.listen(this.port, '127.0.0.1', r));
  }
  async stop(): Promise<void> {
    for (const s of this.sockets) s.destroy();
    await new Promise((r) => this.server?.close(r));
  }
}

async function freePort(): Promise<number> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  const p = (s.address() as { port: number }).port;
  await new Promise((r) => s.close(r));
  return p;
}

const config = (redisUrl: string) =>
  ({
    get: (k: string) =>
      k === 'REDIS_URL' ? redisUrl : k === 'REDIS_TIMEOUT_MS' ? 500 : undefined,
  }) as never;

/** Is this instance serving from its cache? (a second lookup does not load) */
async function caching(c: AuthCache): Promise<boolean> {
  let loads = 0;
  const key = `probe-${Math.random()}`;
  const load = () => Promise.resolve((loads += 1));
  await c.remember(key, load);
  await c.remember(key, load);
  return loads === 1;
}
async function until(fn: () => Promise<boolean>, ms = 8000): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return;
    await wait(50);
  }
  throw new Error('condition not reached');
}

describe.skipIf(!url)('AuthCache across replicas (redis)', () => {
  const live: AuthCache[] = [];
  const proxies: Proxy[] = [];
  afterEach(async () => {
    for (const c of live.splice(0)) c.onModuleDestroy();
    for (const p of proxies.splice(0)) await p.stop();
    delete process.env.AUTH_CACHE_PUBSUB;
  });
  const make = (u: string) => {
    const c = new AuthCache(config(u));
    c.onModuleInit();
    live.push(c);
    return c;
  };

  it('an invalidation on replica A clears replica B within a moment', async () => {
    const a = make(url!);
    const b = make(url!);
    await until(() => caching(b));
    await until(() => caching(a));
    let roles = ['A', 'B'];
    const load = () => Promise.resolve(roles);
    expect(await b.remember('k', load)).toEqual(['A', 'B']);
    roles = ['A'];
    expect(await b.remember('k', load)).toEqual(['A', 'B']); // still the cached entry
    await a.invalidate();
    await until(async () => ((await b.remember('k', load)) ?? []).length === 1);
  });

  it('a revoke during a Redis outage is never served after the replica reconnects', async () => {
    const proxy = new Proxy(await freePort());
    proxies.push(proxy);
    await proxy.start();
    const a = make(url!); // the replica that performs the revoke, direct to Redis
    const b = make(`redis://127.0.0.1:${proxy.port}`);
    await until(() => caching(b));

    let roles = ['OWNER', 'AUDITOR'];
    const load = () => Promise.resolve([...roles]);
    expect(await b.remember('m', load)).toEqual(['OWNER', 'AUDITOR']); // cached on B

    await proxy.stop(); // B loses Redis
    roles = ['AUDITOR']; // the OWNER role is revoked during the outage
    await a.invalidate(); // B never hears it
    // B notices and stops serving its cache: the revoked role is never returned.
    await until(async () => ((await b.remember('m', load)) ?? []).length === 1);
    expect(await b.remember('m', load)).toEqual(['AUDITOR']);
    expect(await caching(b)).toBe(false); // bypassed while down

    await proxy.start(); // Redis is back for B
    await until(() => caching(b));
    expect(await b.remember('m', load)).toEqual(['AUDITOR']); // never the old entry
  }, 30_000);

  it('start-up does not wait for Redis, and without it every lookup goes to the database', async () => {
    const port = await freePort(); // nothing listens here
    const c = new AuthCache(config(`redis://127.0.0.1:${port}`));
    const started = Date.now();
    c.onModuleInit();
    live.push(c);
    // Blocking on the connect would take the full REDIS_TIMEOUT_MS (500 here); the margin keeps a busy host from flaking.
    expect(Date.now() - started).toBeLessThan(450);
    let loads = 0;
    const load = () => Promise.resolve((loads += 1));
    await c.remember('k', load);
    await c.remember('k', load);
    expect(loads).toBe(2);
  });

  it('AUTH_CACHE_PUBSUB=false turns the cache off entirely', async () => {
    process.env.AUTH_CACHE_PUBSUB = 'false';
    const c = make(url!);
    await wait(300);
    expect(await caching(c)).toBe(false);
    const local = new AuthCache(); // no Redis configured either
    expect(await caching(local)).toBe(false);
  });
});
