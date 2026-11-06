import { viewJob, type AiJobState } from './ai-job.store';

export interface JobEventsOptions {
  read: () => Promise<AiJobState | undefined>;
  send: (event: string, data: unknown) => void;
  isClosed: () => boolean;
  sleep: (ms: number) => Promise<void>;
  now: () => number;
  pollMs?: number;
  /** One connection never lives longer than this; the client reconnects (state is the source of truth). */
  maxMs?: number;
}

/** Well under every proxy's limit (Cloudflare 100 s); heartbeats keep it alive inside that. */
export const JOB_STREAM_MAX_MS = 55_000;

/**
 * Feeds one SSE connection from a job's stored state: `progress` whenever status, phase or tokens
 * change, `done` once it is ready, failed or cancelled, `reconnect` when this connection has lived
 * `maxMs` (the client opens a new one and gets the current state at once). Because the stored state
 * is the source of truth, a dropped or proxy-cut connection loses nothing.
 */
export async function pumpJobEvents(
  o: JobEventsOptions,
): Promise<'done' | 'reconnect' | 'closed' | 'gone'> {
  const started = o.now();
  let last = '';
  while (!o.isClosed()) {
    const stored = await o.read();
    if (!stored) {
      o.send('error', { code: 'not_found' });
      return 'gone';
    }
    const job = viewJob(stored, new Date(o.now()));
    const shown = `${job.status}|${job.phase}|${job.outputTokens}`;
    if (
      job.status === 'ready' ||
      job.status === 'failed' ||
      job.status === 'cancelled'
    ) {
      o.send('done', publicView(job));
      return 'done';
    }
    if (shown !== last) {
      last = shown;
      o.send('progress', publicView(job));
    }
    if (o.now() - started >= (o.maxMs ?? JOB_STREAM_MAX_MS)) {
      o.send('reconnect', {});
      return 'reconnect';
    }
    await o.sleep(o.pollMs ?? 1000);
  }
  return 'closed';
}

/** What the console sees: no meter key, no tenant or user ids. */
export function publicView(job: AiJobState) {
  return {
    id: job.id,
    kind: job.kind,
    status: job.status,
    phase: job.phase,
    outputTokens: job.outputTokens,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
    result: job.result ?? null,
    error: job.error ?? null,
  };
}
