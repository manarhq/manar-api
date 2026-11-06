/** A workspace (or the whole platform) spending far more today than it usually does. */
export interface SpendSpike {
  tenantId: string | null;
  todayUsd: number;
  baselineUsd: number;
  ratio: number | null;
}

export const SPIKE_DEFAULTS = {
  /** Today must be at least this many times the baseline... */
  multiplier: 3,
  /** ...and at least this many dollars, so $0.02 against $0.005 is not an alert. */
  floorUsd: 5,
  /** Baseline = median of the daily spend over the days before today that had any. */
  lookbackDays: 7,
} as const;

export function median(values: number[]): number {
  if (values.length === 0) return 0;
  const s = [...values].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid]! : (s[mid - 1]! + s[mid]!) / 2;
}

/**
 * `today` is spend per key (a tenant id, or `null` for the platform total); `history` is the same
 * key's daily spend on earlier days (days with no spend omitted). A key with no history spikes
 * when it passes the floor alone: a brand-new workspace burning money is the case to catch.
 */
export function detectSpikes(
  today: Map<string | null, number>,
  history: Map<string | null, number[]>,
  options: Partial<typeof SPIKE_DEFAULTS> = {},
): SpendSpike[] {
  const { multiplier, floorUsd } = { ...SPIKE_DEFAULTS, ...options };
  const out: SpendSpike[] = [];
  for (const [tenantId, todayUsd] of today) {
    const baselineUsd = median(history.get(tenantId) ?? []);
    const over =
      todayUsd >= floorUsd &&
      (baselineUsd === 0 || todayUsd >= multiplier * baselineUsd);
    if (over)
      out.push({
        tenantId,
        todayUsd,
        baselineUsd,
        ratio: baselineUsd === 0 ? null : todayUsd / baselineUsd,
      });
  }
  return out.sort((a, b) => b.todayUsd - a.todayUsd);
}
