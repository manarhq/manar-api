import { EventEmitter } from 'node:events';
import {
  BadRequestException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { FastifyReply } from 'fastify';
import type { AuthContext } from '../../auth/auth-context';
import type { DomainEventEnvelope } from '../domain-event-envelope';
import {
  LiveEventsController,
  MAX_BUFFERED_BYTES,
  parseLivePrefix,
} from './live-events.controller';
import { registry } from '../../metrics/metrics';
import type { RedisPubSubService } from './redis-pubsub.service';

class FakeRaw extends EventEmitter {
  order: string[] = [];
  chunks: string[] = [];
  writableLength = 0;
  writeHead = vi.fn(() => {
    this.order.push('writeHead');
  });
  write = vi.fn((chunk: string) => {
    this.chunks.push(chunk);
    return true;
  });
  destroy = vi.fn(() => {
    this.emit('close');
  });
}

const auth = { tenant: { id: 'tenant-a' } } as unknown as AuthContext;
const env = (eventType: string): DomainEventEnvelope =>
  ({ eventType, tenantId: 'tenant-a' }) as unknown as DomainEventEnvelope;

let raw: FakeRaw;
let deliver: (e: DomainEventEnvelope) => void;
let unsubscribe: ReturnType<typeof vi.fn>;
let subscribeTenant: ReturnType<typeof vi.fn>;
let controller: LiveEventsController;
const reply = () => ({ raw }) as unknown as FastifyReply;

beforeEach(() => {
  raw = new FakeRaw();
  unsubscribe = vi.fn(() => Promise.resolve());
  subscribeTenant = vi.fn((_tenant: string, cb: typeof deliver) => {
    raw.order.push('subscribe');
    deliver = cb;
    return Promise.resolve({ unsubscribe });
  });
  controller = new LiveEventsController({
    subscribeTenant,
  } as unknown as RedisPubSubService);
});

const frames = () => raw.chunks.filter((c) => c.startsWith('event:'));

describe('GET /events/live', () => {
  it('subscribes to the caller tenant BEFORE it answers 200', async () => {
    await controller.live(auth, reply());
    expect(subscribeTenant).toHaveBeenCalledWith(
      'tenant-a',
      expect.any(Function),
    );
    expect(raw.order).toEqual(['subscribe', 'writeHead']);
    expect(raw.chunks[0]).toBe(': connected\n\n');
  });

  it('answers 503 enforcement_dependency_unavailable and writes nothing when the subscribe fails', async () => {
    subscribeTenant.mockRejectedValueOnce(new Error('redis down'));
    const error = await controller.live(auth, reply()).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ServiceUnavailableException);
    expect(
      JSON.stringify((error as ServiceUnavailableException).getResponse()),
    ).toContain('enforcement_dependency_unavailable');
    expect(raw.writeHead).not.toHaveBeenCalled();
    expect(raw.write).not.toHaveBeenCalled();
  });

  it('forwards every event without a prefix, and only matching ones with one', async () => {
    await controller.live(auth, reply());
    deliver(env('approval.requested'));
    deliver(env('task.created'));
    expect(frames()).toHaveLength(2);

    raw = new FakeRaw();
    await controller.live(auth, reply(), 'approval.');
    deliver(env('task.created'));
    deliver(env('approval.denied'));
    deliver(env('approvalX.nope'));
    expect(frames()).toHaveLength(1);
    expect(frames()[0]).toContain('approval.denied');
  });

  it('rejects a prefix outside the allowlist with 400, before subscribing', async () => {
    for (const bad of [
      'audit.',
      'approval',
      '.*',
      'approval.x',
      ['approval.', 'task.'],
    ]) {
      await expect(
        controller.live(auth, reply(), bad as unknown as string),
      ).rejects.toBeInstanceOf(BadRequestException);
    }
    expect(subscribeTenant).not.toHaveBeenCalled();
  });

  it('treats an absent or empty prefix as the full feed', () => {
    expect(parseLivePrefix(undefined)).toBeUndefined();
    expect(parseLivePrefix('')).toBeUndefined();
    expect(parseLivePrefix('approval.')).toBe('approval.');
  });

  it('closes a connection whose unsent data passes the cap, and counts it', async () => {
    await controller.live(auth, reply());
    deliver(env('approval.requested'));
    expect(raw.destroy).not.toHaveBeenCalled();

    raw.writableLength = MAX_BUFFERED_BYTES + 1;
    deliver(env('approval.requested'));
    expect(raw.destroy).toHaveBeenCalledTimes(1);
    expect(await registry.metrics()).toMatch(
      /manar_live_stream_closed_total\{[^}]*reason="backpressure"[^}]*\} 1/,
    );
    expect(unsubscribe).toHaveBeenCalledTimes(1); // released through the close handler
    const before = raw.write.mock.calls.length;
    deliver(env('approval.requested'));
    expect(raw.write.mock.calls.length).toBe(before); // nothing more is written
  });

  it('releases the subscription once when the client leaves', async () => {
    await controller.live(auth, reply());
    raw.emit('close');
    raw.emit('error', new Error('reset'));
    expect(unsubscribe).toHaveBeenCalledTimes(1);
  });

  it('does not leak a subscription when the client leaves while Redis is still being asked', async () => {
    let resolve!: (v: { unsubscribe: typeof unsubscribe }) => void;
    subscribeTenant.mockReturnValueOnce(
      new Promise((r) => {
        resolve = r;
      }),
    );
    const pending = controller.live(auth, reply());
    raw.emit('close');
    resolve({ unsubscribe });
    await pending;
    expect(unsubscribe).toHaveBeenCalledTimes(1);
    expect(raw.writeHead).not.toHaveBeenCalled();
  });
});
