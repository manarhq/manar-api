import type { FastifyReply } from 'fastify';

/**
 * Cloudflare cuts a response that sends nothing for 100 s. A comment line at least this often
 * keeps every stream below that, with room for a slow hop in between (performance program,
 * decision 5: at least every 15 s).
 */
export const SSE_HEARTBEAT_MS = 10_000;

export interface SseStream {
  /** One named event. `data` is JSON-encoded. A no-op once the client has gone. */
  send(event: string, data: unknown): void;
  /** Aborts when the client disconnects: pass it to anything that should stop (the model call). */
  readonly signal: AbortSignal;
  readonly closed: boolean;
  /** Ends the response. Safe to call twice. */
  end(): void;
}

/**
 * Takes over a Fastify reply as a Server-Sent Events stream. Headers stop every hop from holding
 * the stream back: `no-transform` (no compression, no rewriting), `X-Accel-Buffering: no` (nginx),
 * and the socket is flushed per write (no Nagle delay). A comment heartbeat goes out every
 * `heartbeatMs` for as long as the stream is open.
 *
 * Call it only after everything that can fail with a normal HTTP status (validation, quota,
 * permissions) has been checked: once this runs the status line is 200 and a later failure is an
 * `error` event.
 */
export function openSse(
  reply: FastifyReply,
  heartbeatMs = SSE_HEARTBEAT_MS,
): SseStream {
  reply.hijack();
  const raw = reply.raw;
  raw.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  raw.socket?.setNoDelay(true);
  const abort = new AbortController();
  let closed = false;

  const write = (chunk: string): void => {
    if (closed || raw.writableEnded) return;
    raw.write(chunk);
  };
  const timer = setInterval(() => write(': heartbeat\n\n'), heartbeatMs);
  timer.unref?.();
  const finish = (): void => {
    if (closed) return;
    closed = true;
    clearInterval(timer);
    abort.abort();
  };
  raw.on('close', finish);
  raw.on('error', finish);

  write(': open\n\n');

  return {
    send: (event, data) =>
      write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`),
    signal: abort.signal,
    get closed() {
      return closed;
    },
    end: () => {
      const wasClosed = closed;
      finish();
      if (!wasClosed && !raw.writableEnded) raw.end();
    },
  };
}
