/* eslint-disable @typescript-eslint/require-await -- test doubles with async signatures */
import { EventEmitter } from 'node:events';
import { HttpException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import type { AuthContext } from '../auth/auth-context';
import { AssistantController } from './assistant.controller';
import type { AssistantService, ChatHooks } from './assistant.service';

class FakeRaw extends EventEmitter {
  chunks: string[] = [];
  writableEnded = false;
  socket = { setNoDelay: vi.fn() };
  writeHead = vi.fn();
  write(c: string) {
    this.chunks.push(c);
  }
  end() {
    this.writableEnded = true;
  }
  events() {
    return this.chunks
      .filter((c) => c.startsWith('event:'))
      .map((c) => c.split('\n')[0]!.slice(7));
  }
}

const auth = { tenant: { id: 't1' } } as AuthContext;
const reply = (raw: FakeRaw) => ({ hijack: vi.fn(), raw }) as never;
/** A meter that runs the call and gives back (releases) when no model answered. */
const meter = () => {
  const m = {
    released: 0,
    ai: vi.fn(async <T>(_t: string, fn: () => Promise<T>) => {
      const r = await fn();
      if ((r as { available?: boolean }).available === false) m.released++;
      return r;
    }),
  };
  return m;
};

describe('POST /assistant/chat/stream', () => {
  it('streams tokens then the final answer, and closes', async () => {
    const raw = new FakeRaw();
    const assistant = {
      chat: vi.fn(async (_a, _b, _c, hooks: ChatHooks) => {
        hooks.onReady?.();
        hooks.onToken?.('Hel');
        hooks.onTools?.(['list_pending_approvals']);
        hooks.onToken?.('lo');
        return {
          available: true,
          answer: 'Hello',
          sources: [],
          suggestions: [],
          toolsUsed: [],
        };
      }),
    };
    const c = new AssistantController(
      assistant as unknown as AssistantService,
      meter() as never,
    );
    await c.chatStream(auth, 'Bearer x', {}, reply(raw));
    expect(raw.events()).toEqual(['token', 'tool', 'token', 'done']);
    expect(raw.chunks.join('')).toContain('data: {"t":"Hel"}');
    expect(raw.writableEnded).toBe(true);
  });

  it('answers a refusal before the stream starts as a normal HTTP error', async () => {
    const raw = new FakeRaw();
    const assistant = {
      chat: vi.fn(() => Promise.reject(new HttpException('slow down', 429))),
    };
    const c = new AssistantController(assistant as never, meter() as never);
    await expect(
      c.chatStream(auth, 'Bearer x', {}, reply(raw)),
    ).rejects.toMatchObject({
      status: 429,
    });
    expect(raw.writeHead).not.toHaveBeenCalled();
  });

  it('reports a failure after the stream started as an error event', async () => {
    const raw = new FakeRaw();
    const assistant = {
      chat: vi.fn(async (_a, _b, _c, hooks: ChatHooks) => {
        hooks.onReady?.();
        throw new HttpException({ reason: 'llm_token_quota_exhausted' }, 403);
      }),
    };
    const c = new AssistantController(assistant as never, meter() as never);
    await c.chatStream(auth, 'Bearer x', {}, reply(raw));
    expect(raw.events()).toEqual(['error']);
    expect(raw.chunks.join('')).toContain('"code":403');
    expect(raw.writableEnded).toBe(true);
  });

  it('stopping after words were written is still a used AI action (no refund)', async () => {
    const raw = new FakeRaw();
    const m = meter();
    const assistant = {
      chat: vi.fn(async (_a, _b, _c, hooks: ChatHooks) => {
        hooks.onReady?.();
        hooks.onToken?.('partial');
        raw.emit('close'); // the person pressed stop
        return { available: false, reason: 'model_unavailable' };
      }),
    };
    const c = new AssistantController(assistant as never, m as never);
    await c.chatStream(auth, 'Bearer x', {}, reply(raw));
    expect(m.released).toBe(0);
  });

  it('stopping before any word was written is given back', async () => {
    const raw = new FakeRaw();
    const m = meter();
    const assistant = {
      chat: vi.fn(async (_a, _b, _c, hooks: ChatHooks) => {
        hooks.onReady?.();
        raw.emit('close');
        return { available: false, reason: 'model_unavailable' };
      }),
    };
    const c = new AssistantController(assistant as never, m as never);
    await c.chatStream(auth, 'Bearer x', {}, reply(raw));
    expect(m.released).toBe(1);
  });
});
