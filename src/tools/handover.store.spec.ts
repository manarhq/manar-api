import { afterEach, describe, expect, it, vi } from 'vitest';
import type { OpenBaoKvClient } from '../openbao/openbao-kv.client';
import { HANDOVER_TTL_MS, HandoverStore } from './handover.store';

/** KV v1 semantics: one value per path, no versions, delete is final. */
function fakeKv(down = false) {
  const data = new Map<string, Record<string, unknown>>();
  const fail = () =>
    Promise.reject(new Error('OpenBao KV API failed with HTTP 503'));
  const kv = {
    readV1: (p: string) =>
      down ? fail() : Promise.resolve(data.get(p) ?? null),
    writeV1: (p: string, d: Record<string, unknown>) =>
      down ? fail() : Promise.resolve(void data.set(p, d)),
    deleteV1: (p: string) =>
      down ? fail() : Promise.resolve(void data.delete(p)),
    listV1: (p: string) => {
      if (down) return fail();
      const prefix = `${p.replace(/\/$/, '')}/`;
      const keys = new Set<string>();
      for (const k of data.keys()) {
        if (!k.startsWith(prefix)) continue;
        const rest = k.slice(prefix.length);
        keys.add(rest.includes('/') ? `${rest.split('/')[0]}/` : rest);
      }
      return Promise.resolve([...keys]);
    },
  };
  return { data, store: new HandoverStore(kv as unknown as OpenBaoKvClient) };
}

const secret = { temporaryPassword: 'Tmp-Never-Logged-1!' };

describe('HandoverStore (ADR-0011)', () => {
  afterEach(() => vi.restoreAllMocks());

  it('stores only the value and its creation time, and hands it out once', async () => {
    const { data, store } = fakeKv();
    await store.put('t1', 'a1', secret);
    expect([...data.values()]).toEqual([
      {
        value: JSON.stringify(secret),
        createdAt: expect.any(Number) as unknown,
      },
    ]);
    expect(await store.take('t1', 'a1')).toEqual(secret);
    expect(await store.take('t1', 'a1')).toBeNull();
    expect(data.size).toBe(0);
  });

  it('never hands out an expired value, and the sweep deletes it for good', async () => {
    const { data, store } = fakeKv();
    await store.put('t1', 'old', secret);
    await store.put('t2', 'old', secret);
    const later = Date.now() + HANDOVER_TTL_MS + 1;
    await store.put('t1', 'fresh', secret);
    data.get('handover/t1/fresh')!.createdAt = later;
    vi.spyOn(Date, 'now').mockReturnValue(later);

    expect(await store.sweep()).toBe(2);
    expect([...data.keys()]).toEqual(['handover/t1/fresh']);
    expect(await store.take('t1', 'old')).toBeNull();

    await store.put('t3', 'x', secret);
    vi.spyOn(Date, 'now').mockReturnValue(later + HANDOVER_TTL_MS + 1);
    expect(await store.take('t3', 'x')).toBeNull();
    expect(data.has('handover/t3/x')).toBe(false);
  });

  it('fails, with no fallback, when OpenBao is unavailable', async () => {
    const { store } = fakeKv(true);
    await expect(store.put('t1', 'a1', secret)).rejects.toThrow('HTTP 503');
    await expect(store.take('t1', 'a1')).rejects.toThrow('HTTP 503');
  });
});
