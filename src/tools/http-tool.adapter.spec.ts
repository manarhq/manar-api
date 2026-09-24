import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { ConfigService } from '@nestjs/config';
import { afterEach, describe, expect, it } from 'vitest';
import { HttpToolAdapter } from './http-tool.adapter';
import type { ToolActionRecord, ToolRecord } from './tool-registry.service';

/**
 * Gate 0 finding R1: a mutating or destructive action is sent once, and a
 * lost answer is `outcomeUnknown`, never a retry. Fixtures are real local
 * HTTP servers that answer badly on purpose.
 */

let server: Server | undefined;
afterEach(
  () =>
    new Promise<void>((resolve) =>
      server ? server.close(() => resolve()) : resolve(),
    ),
);

/** Starts a server running `handler`; returns its base URL and a hit counter. */
async function fixture(
  handler: Parameters<typeof createServer>[1],
): Promise<{ baseEndpoint: string; hits: () => number }> {
  let count = 0;
  server = createServer((req, res) => {
    count++;
    handler?.(req, res);
  });
  await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return { baseEndpoint: `http://127.0.0.1:${port}`, hits: () => count };
}

const adapter = new HttpToolAdapter({
  get: () => '127.0.0.1',
} as unknown as ConfigService<never, true>);

function tool(baseEndpoint: string): ToolRecord {
  return { name: 'entra', baseEndpoint } as ToolRecord;
}

function action(sideEffects: Partial<ToolActionRecord>): ToolActionRecord {
  return {
    name: 'disable-user',
    inputSchema: null,
    mutating: false,
    destructive: false,
    ...sideEffects,
  } as ToolActionRecord;
}

const invoke = (baseEndpoint: string, a: ToolActionRecord) =>
  adapter.invoke(tool(baseEndpoint), a, 'user-1', {}, 'secret');

describe('HttpToolAdapter side-effect-aware retries (R1)', () => {
  it('sends a mutating action once and reports UNKNOWN when the connection drops after sending', async () => {
    const { baseEndpoint, hits } = await fixture((req) => req.socket.destroy());

    const result = await invoke(baseEndpoint, action({ mutating: true }));

    expect(hits()).toBe(1);
    expect(result).toMatchObject({ success: false, outcomeUnknown: true });
  });

  it('reports a 5xx on a destructive action as UNKNOWN without retrying', async () => {
    const { baseEndpoint, hits } = await fixture((_req, res) => {
      res.statusCode = 502;
      res.end();
    });

    const result = await invoke(baseEndpoint, action({ destructive: true }));

    expect(hits()).toBe(1);
    expect(result).toMatchObject({ success: false, outcomeUnknown: true });
  });

  it('reports a refused connection on a mutating action as a definite FAILURE', async () => {
    const { baseEndpoint } = await fixture(() => undefined);
    await new Promise<void>((resolve) => server!.close(() => resolve()));
    server = undefined;

    const result = await invoke(baseEndpoint, action({ mutating: true }));

    expect(result.success).toBe(false);
    expect(result.outcomeUnknown).toBeUndefined();
  });

  it('still retries a read-only action on a 5xx, and never marks it UNKNOWN', async () => {
    const { baseEndpoint, hits } = await fixture((_req, res) => {
      res.statusCode = 503;
      res.end();
    });

    const result = await invoke(baseEndpoint, action({}));

    expect(hits()).toBe(3);
    expect(result.outcomeUnknown).toBeUndefined();
  });
});
