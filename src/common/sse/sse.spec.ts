import { EventEmitter } from 'node:events';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { openSse, SSE_HEARTBEAT_MS } from './sse';

class FakeRaw extends EventEmitter {
  headers: Record<string, string> = {};
  chunks: string[] = [];
  writableEnded = false;
  socket = { setNoDelay: vi.fn() };
  writeHead(_status: number, headers: Record<string, string>) {
    this.headers = headers;
  }
  write(chunk: string) {
    this.chunks.push(chunk);
  }
  end() {
    this.writableEnded = true;
  }
}

function fakeReply() {
  const raw = new FakeRaw();
  const reply = { hijack: vi.fn(), raw };
  return { raw, reply: reply as never };
}

describe('openSse', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('sends headers that stop proxies buffering, compressing or caching', () => {
    const { raw, reply } = fakeReply();
    openSse(reply);
    expect(raw.headers['Content-Type']).toContain('text/event-stream');
    expect(raw.headers['Cache-Control']).toBe('no-cache, no-transform');
    expect(raw.headers['X-Accel-Buffering']).toBe('no');
    expect(raw.socket.setNoDelay).toHaveBeenCalledWith(true);
  });

  it('writes a heartbeat comment at least every 15 seconds, however quiet the model is', () => {
    expect(SSE_HEARTBEAT_MS).toBeLessThanOrEqual(15_000);
    const { raw, reply } = fakeReply();
    openSse(reply);
    vi.advanceTimersByTime(60_000);
    const beats = raw.chunks.filter((c) => c === ': heartbeat\n\n');
    expect(beats.length).toBeGreaterThanOrEqual(4);
  });

  it('frames events as JSON and stops (and aborts) when the client goes away', () => {
    const { raw, reply } = fakeReply();
    const sse = openSse(reply);
    sse.send('token', { t: 'hi "there"' });
    expect(raw.chunks).toContain(
      'event: token\ndata: {"t":"hi \\"there\\""}\n\n',
    );
    raw.emit('close');
    expect(sse.signal.aborted).toBe(true);
    const before = raw.chunks.length;
    sse.send('token', { t: 'x' });
    vi.advanceTimersByTime(60_000);
    expect(raw.chunks.length).toBe(before);
  });

  it('end() closes the response once', () => {
    const { raw, reply } = fakeReply();
    const sse = openSse(reply);
    sse.end();
    sse.end();
    expect(raw.writableEnded).toBe(true);
    expect(sse.closed).toBe(true);
  });
});
