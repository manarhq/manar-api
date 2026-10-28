import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuditBatcher } from './audit-batcher';

describe('AuditBatcher', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  const echo = () =>
    vi.fn((_key: string, items: number[]) =>
      Promise.resolve(items.map((n) => n * 10)),
    );

  it('flushes items for one key together after 5 ms, each getting its own result', async () => {
    const flush = echo();
    const batcher = new AuditBatcher(flush);
    const results = [1, 2, 3].map((n) => batcher.enqueue('t1', n));

    expect(flush).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(5);

    expect(flush).toHaveBeenCalledTimes(1);
    expect(flush).toHaveBeenCalledWith('t1', [1, 2, 3]);
    await expect(Promise.all(results)).resolves.toEqual([10, 20, 30]);
  });

  it('flushes at once when the batch reaches 500 items', async () => {
    const flush = echo();
    const batcher = new AuditBatcher(flush);
    const results = Array.from({ length: 500 }, (_, i) =>
      batcher.enqueue('t1', i),
    );
    await vi.advanceTimersByTimeAsync(0);

    expect(flush).toHaveBeenCalledTimes(1);
    expect(flush.mock.calls[0]![1]).toHaveLength(500);
    await expect(results[499]).resolves.toBe(4990);
  });

  it('keeps keys in separate flushes', async () => {
    const flush = echo();
    const batcher = new AuditBatcher(flush);
    void batcher.enqueue('a', 1);
    void batcher.enqueue('b', 2);
    await vi.advanceTimersByTimeAsync(5);

    expect(flush).toHaveBeenCalledTimes(2);
    expect(flush.mock.calls.map((c) => c[0]).sort()).toEqual(['a', 'b']);
  });

  it('rejects every item of a failed batch and keeps working afterwards', async () => {
    const flush = vi
      .fn<(key: string, items: number[]) => Promise<number[]>>()
      .mockRejectedValueOnce(new Error('db down'))
      .mockImplementation((_k, items) => Promise.resolve(items));
    const batcher = new AuditBatcher(flush);
    const failed = [batcher.enqueue('t1', 1), batcher.enqueue('t1', 2)];
    for (const p of failed) void p.catch(() => undefined);
    await vi.advanceTimersByTimeAsync(5);

    for (const p of failed) await expect(p).rejects.toThrow('db down');

    const next = batcher.enqueue('t1', 3);
    await vi.advanceTimersByTimeAsync(5);
    await expect(next).resolves.toBe(3);
  });

  it('rejects the batch when flush returns the wrong number of results', async () => {
    const flush = vi.fn(() => Promise.resolve([1]));
    const batcher = new AuditBatcher(flush);
    const results = [batcher.enqueue('t1', 1), batcher.enqueue('t1', 2)];
    for (const p of results) void p.catch(() => undefined);
    await vi.advanceTimersByTimeAsync(5);

    for (const p of results) await expect(p).rejects.toThrow(/results/);
  });

  it('close() flushes what is pending, then refuses new items', async () => {
    const flush = echo();
    const batcher = new AuditBatcher(flush);
    const pending = batcher.enqueue('t1', 4);

    await batcher.close();
    await expect(pending).resolves.toBe(40);
    await expect(batcher.enqueue('t1', 5)).rejects.toThrow(
      'audit batcher closed',
    );
  });

  it('runs one flush per key at a time; items arriving meanwhile go in the next batch', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const calls: number[][] = [];
    const flush = vi.fn(async (_k: string, items: number[]) => {
      calls.push(items);
      if (calls.length === 1) await gate;
      return items;
    });
    const batcher = new AuditBatcher(flush);

    const first = batcher.enqueue('t1', 1);
    await vi.advanceTimersByTimeAsync(5);
    const second = batcher.enqueue('t1', 2);
    await vi.advanceTimersByTimeAsync(20);
    expect(flush).toHaveBeenCalledTimes(1);

    release();
    await expect(first).resolves.toBe(1);
    await vi.advanceTimersByTimeAsync(5);
    await expect(second).resolves.toBe(2);
    expect(calls).toEqual([[1], [2]]);
  });
});
