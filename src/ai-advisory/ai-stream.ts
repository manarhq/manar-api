import type { FastifyReply } from 'fastify';
import { openSse, type SseStream } from '../common/sse/sse';
import type { StreamHooks } from './ai-advisory-client.service';

/** What `UsageMeterService.ai` offers: one metered AI action around `fn`, given back when nothing answered. */
interface Meter {
  ai<T>(
    tenantId: string,
    fn: () => Promise<T>,
    switchedOff?: () => Promise<T | null>,
  ): Promise<T>;
}

/**
 * Runs one long-form AI action (incident summary, audit investigation) as a Server-Sent Events
 * response: `delta` `{t}` events as the model writes, then `done` with the same body the plain
 * endpoint returns, or `error` `{code}`. The stream opens only once `run` says the checks that
 * answer with a normal status (validation, 404, quota 402) have passed, so those stay ordinary
 * JSON errors. Closing the connection stops the model call. A stop after words were written still
 * counts as used (no refund), like an answer that was read.
 */
export async function runAiStream<T extends { available: boolean }>(
  reply: FastifyReply,
  meter: Meter,
  tenantId: string,
  run: (hooks: StreamHooks) => Promise<T>,
  /** Answers instead of `run` when AI is switched off for the workspace (nothing metered or asked). */
  switchedOff?: () => Promise<T | null>,
): Promise<void> {
  let sse: SseStream | undefined;
  let streamed = 0;
  try {
    const result = await meter.ai(
      tenantId,
      async () => {
        const answer = await run({
          onReady: () => {
            sse = openSse(reply);
          },
          onDelta: (t) => {
            streamed += t.length;
            sse?.send('delta', { t });
          },
          get signal() {
            return sse?.signal;
          },
        });
        return !answer.available && streamed > 0 && sse?.signal.aborted
          ? ({ stopped: true } as const)
          : answer;
      },
      switchedOff,
    );
    if ('stopped' in result) return;
    // A request refused before the stream opened (nothing to ask) still answers in the same shape.
    (sse ??= openSse(reply)).send('done', result);
  } catch (error) {
    if (!sse) throw error;
    const status =
      typeof (error as { getStatus?: () => number }).getStatus === 'function'
        ? (error as { getStatus: () => number }).getStatus()
        : 500;
    sse.send('error', { code: status === 500 ? 'internal' : status });
  } finally {
    sse?.end();
  }
}
