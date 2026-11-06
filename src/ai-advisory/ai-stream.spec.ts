/* eslint-disable @typescript-eslint/require-await -- test doubles with async signatures */
import { EventEmitter } from 'node:events';
import { NotFoundException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { runAiStream } from './ai-stream';

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
  names() {
    return this.chunks
      .filter((c) => c.startsWith('event:'))
      .map((c) => c.split('\n')[0]!.slice(7));
  }
}
const reply = (raw: FakeRaw) => ({ hijack: vi.fn(), raw }) as never;
const meter = () => {
  const m = {
    released: 0,
    ai: async <T>(_t: string, fn: () => Promise<T>) => {
      const r = await fn();
      if ((r as { available?: boolean }).available === false) m.released++;
      return r;
    },
  };
  return m;
};

describe('runAiStream', () => {
  it('sends delta events, then the plain endpoint body as done', async () => {
    const raw = new FakeRaw();
    await runAiStream(reply(raw), meter(), 't', async (hooks) => {
      hooks.onReady?.();
      hooks.onDelta?.('Three ');
      hooks.onDelta?.('denials.');
      return { available: true, result: { summary: 'Three denials.' } };
    });
    expect(raw.names()).toEqual(['delta', 'delta', 'done']);
    expect(raw.chunks.join('')).toContain('"summary":"Three denials."');
    expect(raw.writableEnded).toBe(true);
  });

  it('leaves a 404 found before the stream starts as a normal error', async () => {
    const raw = new FakeRaw();
    await expect(
      runAiStream(reply(raw), meter(), 't', () =>
        Promise.reject(new NotFoundException()),
      ),
    ).rejects.toMatchObject({ status: 404 });
    expect(raw.writeHead).not.toHaveBeenCalled();
  });

  it('turns a failure after the stream started into an error event', async () => {
    const raw = new FakeRaw();
    await runAiStream(reply(raw), meter(), 't', async (hooks) => {
      hooks.onReady?.();
      throw new NotFoundException();
    });
    expect(raw.names()).toEqual(['error']);
    expect(raw.chunks.join('')).toContain('"code":404');
  });

  it('gives the action back when nothing was written and the model did not answer', async () => {
    const raw = new FakeRaw();
    const m = meter();
    await runAiStream(reply(raw), m, 't', async (hooks) => {
      hooks.onReady?.();
      return { available: false };
    });
    expect(m.released).toBe(1);
    expect(raw.names()).toEqual(['done']);
  });

  it('does not give it back when the person stopped after words were written', async () => {
    const raw = new FakeRaw();
    const m = meter();
    await runAiStream(reply(raw), m, 't', async (hooks) => {
      hooks.onReady?.();
      hooks.onDelta?.('some words');
      raw.emit('close');
      return { available: false };
    });
    expect(m.released).toBe(0);
  });
});
