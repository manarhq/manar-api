import { describe, expect, it } from 'vitest';
import {
  AI_LATENCY_BUCKET_COUNT,
  addBuckets,
  latencyBucket,
  percentileMs,
} from './ai-latency';
import { detectSpikes, median } from './ai-spike';

describe('latency buckets', () => {
  it('puts a call in the first bucket whose edge it does not pass', () => {
    expect(latencyBucket(0)).toBe(0);
    expect(latencyBucket(250)).toBe(0);
    expect(latencyBucket(251)).toBe(1);
    expect(latencyBucket(999_999)).toBe(AI_LATENCY_BUCKET_COUNT - 1);
  });

  it('estimates p50 and p95 inside the bucket they fall in', () => {
    const counts = new Array<number>(AI_LATENCY_BUCKET_COUNT).fill(0);
    counts[2] = 90; // 500-1000 ms
    counts[6] = 10; // 8000-15000 ms
    const p50 = percentileMs(counts, 0.5);
    const p95 = percentileMs(counts, 0.95);
    expect(p50).toBeGreaterThan(500);
    expect(p50).toBeLessThanOrEqual(1000);
    expect(p95).toBeGreaterThan(8000);
    expect(p95).toBeLessThanOrEqual(15_000);
    expect(percentileMs([], 0.5)).toBe(0);
  });

  it('adds rows of different lengths', () => {
    expect(addBuckets([1, 1], [1, 0, 5]).slice(0, 3)).toEqual([2, 1, 5]);
  });
});

describe('spend spikes', () => {
  it('flags a workspace at three times its median above the floor', () => {
    const spikes = detectSpikes(
      new Map<string | null, number>([
        ['a', 30],
        ['b', 13],
        ['c', 4],
      ]),
      new Map<string | null, number[]>([
        ['a', [8, 10, 12]],
        ['b', [4, 4, 3]],
        ['c', [0.1]],
      ]),
    );
    expect(spikes.map((s) => s.tenantId)).toEqual(['a', 'b']);
    expect(spikes[0]?.ratio).toBeCloseTo(3);
  });

  it('flags a workspace with no history once it passes the floor, and ignores small money', () => {
    const spikes = detectSpikes(
      new Map<string | null, number>([
        ['new', 6],
        ['tiny', 0.04],
      ]),
      new Map(),
    );
    expect(spikes).toEqual([
      { tenantId: 'new', todayUsd: 6, baselineUsd: 0, ratio: null },
    ]);
  });

  it('median of an even list is the middle pair mean', () => {
    expect(median([1, 3, 5, 7])).toBe(4);
  });
});
