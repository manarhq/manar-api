/** Upper edges of the latency buckets in a daily rollup, in ms; one more bucket catches the rest. */
export const AI_LATENCY_BUCKETS_MS = [
  250, 500, 1000, 2000, 4000, 8000, 15_000, 30_000, 60_000, 120_000, 300_000,
] as const;
export const AI_LATENCY_BUCKET_COUNT = AI_LATENCY_BUCKETS_MS.length + 1;

export function latencyBucket(ms: number): number {
  const at = AI_LATENCY_BUCKETS_MS.findIndex((edge) => ms <= edge);
  return at === -1 ? AI_LATENCY_BUCKETS_MS.length : at;
}

/** Adds bucket count arrays of different lengths (older rows). */
export function addBuckets(into: number[], from: readonly number[]): number[] {
  for (let i = 0; i < AI_LATENCY_BUCKET_COUNT; i++)
    into[i] = (into[i] ?? 0) + (from[i] ?? 0);
  return into;
}

/**
 * Percentile (0 to 1) from bucket counts, interpolated inside the bucket it falls in. An estimate
 * as good as the bucket width; the overflow bucket reports its lower edge.
 */
export function percentileMs(counts: readonly number[], q: number): number {
  const total = counts.reduce((a, b) => a + b, 0);
  if (total === 0) return 0;
  const target = q * total;
  let seen = 0;
  for (let i = 0; i < AI_LATENCY_BUCKET_COUNT; i++) {
    const n = counts[i] ?? 0;
    if (n > 0 && seen + n >= target) {
      const low = i === 0 ? 0 : AI_LATENCY_BUCKETS_MS[i - 1]!;
      const high = AI_LATENCY_BUCKETS_MS[i];
      if (high === undefined) return low;
      return Math.round(low + ((target - seen) / n) * (high - low));
    }
    seen += n;
  }
  return AI_LATENCY_BUCKETS_MS[AI_LATENCY_BUCKETS_MS.length - 1]!;
}
