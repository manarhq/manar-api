import type { ConfigService } from '@nestjs/config';
import { describe, expect, it, vi } from 'vitest';
import { McpToolAdapter } from './mcp-tool.adapter';
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
  get: () => '127.0.0.1',
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
