import { EventEmitter } from 'node:events';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ConfigService } from '@nestjs/config';

type Listener = (message: string) => void;

class FakeRedis extends EventEmitter {
  static instances: FakeRedis[] = [];
  static failConnect = false;
  static hangConnect = false;
  channels = new Map<string, Listener>();
  quit = vi.fn(() => Promise.resolve());
  destroy = vi.fn();
  unsubscribe = vi.fn((channel: string) => {
    this.channels.delete(channel);
    return Promise.resolve();
  });
  constructor() {
    super();
    FakeRedis.instances.push(this);
  }
  duplicate(): FakeRedis {
    return new FakeRedis();
  }
  connect(): Promise<void> {
    if (FakeRedis.hangConnect) return new Promise(() => undefined);
    if (FakeRedis.failConnect) return Promise.reject(new Error('redis down'));
    return Promise.resolve();
  }
  subscribe(channel: string, listener: Listener): Promise<void> {
    this.channels.set(channel, listener);
    return Promise.resolve();
  }
  /** Delivers a message as Redis would, to whatever this subscriber listens to. */
  deliver(channel: string, payload: unknown): void {
    this.channels.get(channel)?.(JSON.stringify(payload));
  }
}

vi.mock('redis', () => ({ createClient: () => new FakeRedis() }));

import {
  RedisPubSubService,
  SUBSCRIBE_TIMEOUT_MS,
  tenantLiveChannel,
} from './redis-pubsub.service';

function service(): RedisPubSubService {
  const config = {
    get: (key: string) =>
      key === 'REDIS_URL' ? 'redis://localhost:6379' : undefined,
  } as unknown as ConfigService<never, true>;
  return new RedisPubSubService(config);
}

/** The duplicated subscriber connections (instance 0 of each pair is the throwaway base). */
const subscribers = () =>
  FakeRedis.instances.filter((r) => r.listenerCount('error') > 0);
const subscriberAt = (i: number): FakeRedis => {
  const found = subscribers()[i];
  if (!found) throw new Error(`no subscriber ${i}`);
  return found;
};

const envelope = (tenantId: string, eventType = 'approval.requested') => ({
  eventId: `${tenantId}-1`,
  tenantId,
  eventType,
});

beforeEach(() => {
  FakeRedis.instances = [];
  FakeRedis.failConnect = false;
  FakeRedis.hangConnect = false;
});
afterEach(() => vi.useRealTimers());

describe('RedisPubSubService.subscribeTenant (shared subscriber)', () => {
  it('serves every listener of one tenant from ONE Redis subscriber', async () => {
    const svc = service();
    const a = vi.fn();
    const b = vi.fn();
    await svc.subscribeTenant('t1', a);
    await svc.subscribeTenant('t1', b);
    expect(subscribers()).toHaveLength(1);
    expect(svc.sharedSubscriberCount()).toBe(1);

    subscriberAt(0).deliver(tenantLiveChannel('t1'), envelope('t1'));
    expect(a).toHaveBeenCalledTimes(1);
    expect(b).toHaveBeenCalledTimes(1);
  });

  it('keeps tenants apart: a tenant never hears another tenant, and each has its own subscriber', async () => {
    const svc = service();
    const t1 = vi.fn();
    const t2 = vi.fn();
    await svc.subscribeTenant('t1', t1);
    await svc.subscribeTenant('t2', t2);
    expect(subscribers()).toHaveLength(2);
    const s1 = subscriberAt(0);
    const s2 = subscriberAt(1);
    expect([...s1.channels.keys()]).toEqual([tenantLiveChannel('t1')]);
    expect([...s2.channels.keys()]).toEqual([tenantLiveChannel('t2')]);

    s1.deliver(tenantLiveChannel('t1'), envelope('t1'));
    expect(t1).toHaveBeenCalledTimes(1);
    expect(t2).not.toHaveBeenCalled();
    // Even a message wrongly arriving on t2's connection never reaches t1's listeners.
    s2.deliver(tenantLiveChannel('t2'), envelope('t2'));
    expect(t1).toHaveBeenCalledTimes(1);
    expect(t2).toHaveBeenCalledTimes(1);
  });

  it('unsubscribes and quits only when the last listener leaves, then opens afresh', async () => {
    const svc = service();
    const first = await svc.subscribeTenant('t1', vi.fn());
    const second = await svc.subscribeTenant('t1', vi.fn());
    const sub = subscriberAt(0);

    await first.unsubscribe();
    expect(sub.unsubscribe).not.toHaveBeenCalled();
    expect(sub.quit).not.toHaveBeenCalled();

    await second.unsubscribe();
    expect(sub.unsubscribe).toHaveBeenCalledWith(tenantLiveChannel('t1'));
    expect(sub.quit).toHaveBeenCalledTimes(1);
    expect(svc.sharedSubscriberCount()).toBe(0);

    await svc.subscribeTenant('t1', vi.fn());
    expect(subscribers()).toHaveLength(2);
  });

  it('unsubscribe is idempotent (a double close cannot drop another listener)', async () => {
    const svc = service();
    const keep = vi.fn();
    await svc.subscribeTenant('t1', keep);
    const gone = await svc.subscribeTenant('t1', vi.fn());
    await gone.unsubscribe();
    await gone.unsubscribe();
    subscriberAt(0).deliver(tenantLiveChannel('t1'), envelope('t1'));
    expect(keep).toHaveBeenCalledTimes(1);
    expect(subscriberAt(0).quit).not.toHaveBeenCalled();
  });

  it('a listener that throws, or a frame that does not parse, does not stop the others', async () => {
    const svc = service();
    const ok = vi.fn();
    await svc.subscribeTenant('t1', () => {
      throw new Error('boom');
    });
    await svc.subscribeTenant('t1', ok);
    const sub = subscriberAt(0);
    sub.channels.get(tenantLiveChannel('t1'))?.('{not json');
    expect(ok).not.toHaveBeenCalled();
    sub.deliver(tenantLiveChannel('t1'), envelope('t1'));
    expect(ok).toHaveBeenCalledTimes(1);
  });

  it('rejects when Redis is down, cleans up, and the next caller tries afresh', async () => {
    const svc = service();
    FakeRedis.failConnect = true;
    await expect(svc.subscribeTenant('t1', vi.fn())).rejects.toThrow(
      'redis down',
    );
    expect(subscriberAt(0).destroy).toHaveBeenCalled();
    expect(svc.sharedSubscriberCount()).toBe(0);

    FakeRedis.failConnect = false;
    const ok = vi.fn();
    await svc.subscribeTenant('t1', ok);
    subscriberAt(1).deliver(tenantLiveChannel('t1'), envelope('t1'));
    expect(ok).toHaveBeenCalledTimes(1);
  });

  it('gives up after SUBSCRIBE_TIMEOUT_MS instead of hanging the request', async () => {
    vi.useFakeTimers();
    const svc = service();
    FakeRedis.hangConnect = true;
    const pending = svc.subscribeTenant('t1', vi.fn());
    const assertion = expect(pending).rejects.toThrow('timed out');
    await vi.advanceTimersByTimeAsync(SUBSCRIBE_TIMEOUT_MS + 1);
    await assertion;
    expect(svc.sharedSubscriberCount()).toBe(0);
  });

  it('closes every shared subscriber on shutdown', async () => {
    const svc = service();
    await svc.subscribeTenant('t1', vi.fn());
    await svc.subscribeTenant('t2', vi.fn());
    await svc.onModuleDestroy();
    expect(subscribers().every((s) => s.destroy.mock.calls.length === 1)).toBe(
      true,
    );
    expect(svc.sharedSubscriberCount()).toBe(0);
  });
});
