/**
 * Group commit for audit writes (docs/audit-chain.md). Items are queued per
 * key (the tenant id) and handed to `flush` together, at most `maxWaitMs`
 * after the first one arrived or as soon as `maxBatch` are waiting. One flush
 * per key runs at a time; items that arrive meanwhile go in the next batch.
 *
 * Each `enqueue` promise settles only when its batch's `flush` settles, so a
 * caller that awaits it still knows its event is committed before acting
 * (record-before-execution, ADR-003). A failed flush rejects every item in
 * that batch and nothing else; a flush may instead return an `Error` in an
 * item's slot to reject just that item.
 */
interface Pending<TIn, TOut> {
  item: TIn;
  resolve: (value: TOut) => void;
  reject: (error: unknown) => void;
}

interface KeyState<TIn, TOut> {
  queue: Pending<TIn, TOut>[];
  timer: NodeJS.Timeout | null;
  inFlight: Promise<void> | null;
}

export class AuditBatcher<TIn, TOut> {
  private readonly maxWaitMs: number;
  private readonly maxBatch: number;
  private readonly keys = new Map<string, KeyState<TIn, TOut>>();
  private closed = false;

  constructor(
    private readonly flush: (
      key: string,
      items: TIn[],
    ) => Promise<(TOut | Error)[]>,
    opts: { maxWaitMs?: number; maxBatch?: number } = {},
  ) {
    this.maxWaitMs = opts.maxWaitMs ?? 5;
    this.maxBatch = opts.maxBatch ?? 500;
  }

  enqueue(key: string, item: TIn): Promise<TOut> {
    if (this.closed) return Promise.reject(new Error('audit batcher closed'));
    const state = this.stateFor(key);
    return new Promise<TOut>((resolve, reject) => {
      state.queue.push({ item, resolve, reject });
      this.schedule(key, state);
    });
  }

  /** Flushes everything still queued, then refuses new items. */
  async close(): Promise<void> {
    this.closed = true;
    for (;;) {
      const busy = [...this.keys.entries()].filter(
        ([, s]) => s.inFlight !== null || s.queue.length > 0,
      );
      if (busy.length === 0) return;
      await Promise.all(busy.map(([key, s]) => s.inFlight ?? this.run(key, s)));
    }
  }

  private stateFor(key: string): KeyState<TIn, TOut> {
    let state = this.keys.get(key);
    if (!state) {
      state = { queue: [], timer: null, inFlight: null };
      this.keys.set(key, state);
    }
    return state;
  }

  private schedule(key: string, state: KeyState<TIn, TOut>): void {
    if (state.inFlight) return; // the running flush reschedules when it ends
    if (state.queue.length >= this.maxBatch) {
      void this.run(key, state);
    } else if (state.timer === null && state.queue.length > 0) {
      state.timer = setTimeout(() => void this.run(key, state), this.maxWaitMs);
    }
  }

  private run(key: string, state: KeyState<TIn, TOut>): Promise<void> {
    if (state.timer !== null) {
      clearTimeout(state.timer);
      state.timer = null;
    }
    if (state.inFlight) return state.inFlight;
    const batch = state.queue.splice(0, this.maxBatch);
    if (batch.length === 0) return Promise.resolve();

    state.inFlight = (async () => {
      try {
        const results = await this.flush(
          key,
          batch.map((p) => p.item),
        );
        if (results.length !== batch.length) {
          throw new Error(
            `audit flush returned ${results.length} results for ${batch.length} items`,
          );
        }
        batch.forEach((p, i) => {
          const result = results[i];
          if (result instanceof Error) p.reject(result);
          else p.resolve(result as TOut);
        });
      } catch (error) {
        batch.forEach((p) => p.reject(error));
      } finally {
        state.inFlight = null;
        this.schedule(key, state);
      }
    })();
    return state.inFlight;
  }
}
