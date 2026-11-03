import type { ConfigService } from '@nestjs/config';
import { describe, expect, it, vi } from 'vitest';
import { guardedMcpFetch, McpToolAdapter } from './mcp-tool.adapter';
import {
  OutboundResponseTooLargeError,
  UnsafeOutboundUrlError,
} from '../common/ssrf/url-safety';
import type { ToolActionRecord, ToolRecord } from './tool-registry.service';

/** Gate 0 finding R1 on the MCP path: a lost answer after `tools/call` is UNKNOWN. */

const client = vi.hoisted(() => ({
  connect: vi.fn(),
  callTool: vi.fn(),
  close: vi.fn(() => Promise.resolve()),
}));
vi.mock('@modelcontextprotocol/sdk/client/index.js', () => ({
  Client: vi.fn(function Client() {
    return client;
  }),
}));

const adapter = new McpToolAdapter({
  get: (key: string) =>
    ({ SSRF_ALLOWED_HOSTS: '127.0.0.1', SSRF_ALLOW_LOOPBACK: true })[key],
} as unknown as ConfigService<never, true>);

const tool = {
  name: 'defender',
  baseEndpoint: 'http://127.0.0.1:9/mcp',
} as unknown as ToolRecord;

function action(mutating: boolean): ToolActionRecord {
  return {
    name: 'isolate-host',
    inputSchema: null,
    mutating,
    destructive: false,
  } as unknown as ToolActionRecord;
}

describe('McpToolAdapter outcome (R1)', () => {
  it('reports UNKNOWN when a mutating tools/call times out after being sent', async () => {
    client.connect.mockResolvedValue(undefined);
    client.callTool.mockRejectedValue(new Error('Request timed out'));

    const result = await adapter.invoke(tool, action(true), 'host-1', {}, 'c');

    expect(result).toMatchObject({ success: false, outcomeUnknown: true });
  });

  it('reports a definite FAILURE when connect fails before anything was asked', async () => {
    client.connect.mockRejectedValue(new Error('ECONNREFUSED'));
    client.callTool.mockClear();

    const result = await adapter.invoke(tool, action(true), 'host-1', {}, 'c');

    expect(client.callTool).not.toHaveBeenCalled();
    expect(result.success).toBe(false);
    expect(result.outcomeUnknown).toBeUndefined();
  });

  it('does not mark a read-only call UNKNOWN', async () => {
    client.connect.mockResolvedValue(undefined);
    client.callTool.mockRejectedValue(new Error('Request timed out'));

    const result = await adapter.invoke(tool, action(false), 'host-1', {}, 'c');

    expect(result.outcomeUnknown).toBeUndefined();
  });
});

describe('McpToolAdapter error text', () => {
  it('never returns the SDK error text, which carries upstream bodies', async () => {
    client.connect.mockResolvedValue(undefined);
    client.callTool.mockRejectedValue(
      new Error('Error POSTing to endpoint (HTTP 500): internal secret page'),
    );
    const result = await adapter.invoke(tool, action(false), 'h', {}, 'c');
    expect(result).toEqual({ success: false, errorMessage: 'mcp_call_failed' });
  });

  it('maps a blocked redirect hop to the URL policy code', async () => {
    client.connect.mockRejectedValue(
      new UnsafeOutboundUrlError('http://169.254.169.254/', 'x'),
    );
    const result = await adapter.invoke(tool, action(false), 'h', {}, 'c');
    expect(result.errorMessage).toBe('blocked_by_outbound_url_policy');
  });

  it('hands an isError result text to the broker separately, capped', async () => {
    client.connect.mockResolvedValue(undefined);
    client.callTool.mockResolvedValue({
      isError: true,
      content: [{ type: 'text', text: 'z'.repeat(5_000) }],
    });
    const result = await adapter.invoke(tool, action(false), 'h', {}, 'c');
    expect(result.errorMessage).toBe('mcp_tool_error');
    expect(result.errorDetail).toHaveLength(1_000);
  });
});

describe('guardedMcpFetch', () => {
  const policy = { allowedHosts: new Set<string>(), allowLoopback: false };
  const lookup = (host: string) =>
    Promise.resolve([
      {
        address:
          host === 'mcp.example.test' ? '93.184.216.34' : '169.254.169.254',
        family: 4,
      },
    ]);

  it('re-checks every redirect hop and refuses the metadata service', async () => {
    const fetchImpl = vi.fn(() =>
      Promise.resolve(
        new Response(null, {
          status: 307,
          headers: { location: 'http://metadata.example.test/latest' },
        }),
      ),
    ) as unknown as typeof fetch;
    const f = guardedMcpFetch(policy, new AbortController().signal, {
      lookup,
      fetchImpl,
    });
    await expect(
      f('https://mcp.example.test/mcp', { method: 'GET' }),
    ).rejects.toBeInstanceOf(UnsafeOutboundUrlError);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('errors the body stream once it passes the byte cap', async () => {
    const fetchImpl = vi.fn(() =>
      Promise.resolve(new Response('x'.repeat(64))),
    ) as unknown as typeof fetch;
    const f = guardedMcpFetch(policy, new AbortController().signal, {
      lookup,
      fetchImpl,
      maxBytes: 16,
    });
    const response = await f('https://mcp.example.test/mcp', {
      method: 'POST',
      body: '{}',
    });
    await expect(response.text()).rejects.toBeInstanceOf(
      OutboundResponseTooLargeError,
    );
  });

  it('refuses up front when the declared length is over the cap', async () => {
    const fetchImpl = vi.fn(() =>
      Promise.resolve(
        new Response('x', { headers: { 'content-length': '999' } }),
      ),
    ) as unknown as typeof fetch;
    const f = guardedMcpFetch(policy, new AbortController().signal, {
      lookup,
      fetchImpl,
      maxBytes: 16,
    });
    await expect(
      f('https://mcp.example.test/mcp', { method: 'GET' }),
    ).rejects.toBeInstanceOf(OutboundResponseTooLargeError);
  });

  it('passes the shared deadline to every request', async () => {
    const deadline = new AbortController();
    deadline.abort();
    const fetchImpl = vi.fn((_u: string, init?: RequestInit) =>
      init?.signal?.aborted
        ? Promise.reject(new DOMException('aborted', 'AbortError'))
        : Promise.resolve(new Response('{}')),
    ) as unknown as typeof fetch;
    const f = guardedMcpFetch(policy, deadline.signal, { lookup, fetchImpl });
    await expect(
      f('https://mcp.example.test/mcp', { method: 'GET' }),
    ).rejects.toThrow(/aborted/);
  });
});
