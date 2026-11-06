import { EventEmitter } from 'node:events';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { openSse } from '../common/sse/sse';
import { viewJob, type AiJobState } from './ai-job.store';
import { pumpJobEvents } from './job-events';

const PROXY_LIMIT_MS = 100_000; // Cloudflare cuts a response at 100 s
const JOB_MS = 150_000;

class FakeRaw extends EventEmitter {
  writableEnded = false;
  socket = { setNoDelay: vi.fn() };
  writeHead = vi.fn();
  write = vi.fn();
  end() {
    this.writableEnded = true;
  }
}

const baseJob = (): AiJobState => ({
  id: 'j1',
  tenantId: 't1',
  userId: 'u1',
  kind: 'policy_suggest',
  status: 'running',
  phase: 'drafting',
  outputTokens: 0,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  meterKey: 'ai:job:j1',
  cancelRequested: false,
});

describe('a 150 second job behind a proxy that cuts every response at 100 seconds', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  /** The console's watcher: opens the event stream, and opens it again whenever it ends before `done`. */
  async function watch(serverMaxMs: number) {
    const job = baseJob();
    // The worker: writes progress every 10 s, finishes at 150 s.
    const worker = setInterval(() => {
      job.updatedAt = new Date().toISOString();
      job.outputTokens += 40;
    }, 10_000);
    setTimeout(() => {
      clearInterval(worker);
      job.status = 'ready';
      job.phase = 'done';
      job.updatedAt = new Date().toISOString();
      job.result = {
        available: true,
        policyId: 'p1',
        versionId: 'v1',
        explanation: null,
        confidence: 0.8,
        ruleCount: 3,
      };
    }, JOB_MS);

    const out = {
      connections: 0,
      cutByProxy: 0,
      longestConnectionMs: 0,
      longestSilenceMs: 0,
      done: undefined as unknown,
    };
    while (!out.done) {
      out.connections++;
      const raw = new FakeRaw();
      const opened = Date.now();
      let lastByte = opened;
      const chunks: string[] = [];
      raw.write.mockImplementation((c: string) => {
        out.longestSilenceMs = Math.max(
          out.longestSilenceMs,
          Date.now() - lastByte,
        );
        lastByte = Date.now();
        chunks.push(c);
      });
      const sse = openSse({ hijack: vi.fn(), raw } as never);
      const proxy = setTimeout(() => {
        out.cutByProxy++;
        raw.emit('close'); // the proxy drops the connection
      }, PROXY_LIMIT_MS);
      await pumpJobEvents({
        read: () => Promise.resolve(structuredClone(job)),
        send: (e, d) => sse.send(e, d),
        isClosed: () => sse.closed,
        sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
        now: () => Date.now(),
        maxMs: serverMaxMs,
      });
      clearTimeout(proxy);
      sse.end();
      out.longestConnectionMs = Math.max(
        out.longestConnectionMs,
        Date.now() - opened,
      );
      const text = chunks.join('');
      const m = /event: done\ndata: (.*)\n/.exec(text);
      if (m) out.done = JSON.parse(m[1]!);
    }
    return out;
  }

  it('completes with the server closing connections at 55 s: none is ever cut', async () => {
    const run = watch(55_000);
    await vi.advanceTimersByTimeAsync(JOB_MS + 5_000);
    const out = await run;
    expect(out.done).toMatchObject({
      status: 'ready',
      result: { available: true, versionId: 'v1' },
    });
    expect(out.cutByProxy).toBe(0);
    expect(out.connections).toBeGreaterThanOrEqual(3);
    expect(out.longestConnectionMs).toBeLessThan(PROXY_LIMIT_MS);
    expect(out.longestSilenceMs).toBeLessThanOrEqual(15_000);
  });

  it('still completes if a connection is cut at 100 s: the watcher reconnects and loses nothing', async () => {
    const run = watch(10 * 60_000); // a server that never closes by itself
    await vi.advanceTimersByTimeAsync(JOB_MS + 5_000);
    const out = await run;
    expect(out.cutByProxy).toBeGreaterThanOrEqual(1);
    expect(out.done).toMatchObject({
      status: 'ready',
      result: { policyId: 'p1' },
    });
    expect(out.longestSilenceMs).toBeLessThanOrEqual(15_000);
  });
});

describe('job events', () => {
  it('reports a running job whose worker went silent as failed (stalled)', () => {
    const job = {
      ...baseJob(),
      updatedAt: new Date(Date.now() - 120_000).toISOString(),
    };
    expect(viewJob(job)).toMatchObject({ status: 'failed', error: 'stalled' });
    expect(viewJob({ ...job, status: 'ready' }).status).toBe('ready');
  });

  it('says not_found for a job that is gone', async () => {
    const sent: string[] = [];
    const r = await pumpJobEvents({
      read: () => Promise.resolve(undefined),
      send: (e) => sent.push(e),
      isClosed: () => false,
      sleep: () => Promise.resolve(),
      now: () => Date.now(),
    });
    expect(r).toBe('gone');
    expect(sent).toEqual(['error']);
  });

  it('sends progress only when something changed', async () => {
    const sent: string[] = [];
    let n = 0;
    await pumpJobEvents({
      read: () => {
        n++;
        return Promise.resolve({
          ...baseJob(),
          ...(n > 3 ? { status: 'ready' as const } : {}),
        });
      },
      send: (e) => sent.push(e),
      isClosed: () => false,
      sleep: () => Promise.resolve(),
      now: () => Date.now(),
    });
    expect(sent).toEqual(['progress', 'done']);
  });
});
