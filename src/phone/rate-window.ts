/** Fixed-window counter per key, in memory. ponytail: per pod; move to Redis if the bot needs a global cap. */
export class RateWindow {
  private readonly hits = new Map<string, { n: number; reset: number }>();
  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
  ) {}

  /** True when this hit is within the limit. */
  allow(key: string, now: number = Date.now()): boolean {
    if (this.hits.size > 10_000) {
      for (const [k, v] of this.hits) if (v.reset <= now) this.hits.delete(k);
    }
    const cur = this.hits.get(key);
    if (!cur || cur.reset <= now) {
      this.hits.set(key, { n: 1, reset: now + this.windowMs });
      return true;
    }
    cur.n += 1;
    return cur.n <= this.limit;
  }
}
