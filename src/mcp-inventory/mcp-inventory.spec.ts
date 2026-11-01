import { describe, expect, it, vi } from 'vitest';
import { InventoryRequestSchema } from '../host-coverage/host-tools.service';
import {
  McpServerReportSchema,
  parseMcpServers,
  listMcpServers,
  replaceHostMcpServers,
} from './mcp-inventory';

const server = {
  tool: 'host.cursor',
  name: 'fs',
  transport: 'stdio' as const,
  command: 'npx',
  argCount: 2,
  package: '@modelcontextprotocol/server-filesystem',
  version: '1.0.0',
};

function fakeClient(existing: { toolId: string; name: string }[]) {
  const ops: unknown[] = [];
  const client = {
    hostMcpServer: {
      findMany: vi.fn(() => Promise.resolve(existing)),
      deleteMany: vi.fn((a: unknown) => ({ op: 'delete', a })),
      upsert: vi.fn((a: unknown) => ({ op: 'upsert', a })),
    },
    $transaction: vi.fn((list: unknown[]) => {
      ops.push(...list);
      return Promise.resolve([]);
    }),
  };
  return { client, ops };
}

describe('MCP inventory', () => {
  it('keeps the old body valid and strips anything beyond the allow-list', () => {
    expect(
      InventoryRequestSchema.parse({ tools: [] }).mcpServers,
    ).toBeUndefined();
    const parsed = McpServerReportSchema.parse({
      ...server,
      args: ['--token', 'abc'],
      env: { KEY: 'v' },
    });
    expect(parsed).not.toHaveProperty('args');
    expect(parsed).not.toHaveProperty('env');
    expect(
      McpServerReportSchema.safeParse({ ...server, transport: 'ftp' }).success,
    ).toBe(false);
  });

  it('cuts every field down again, whatever the device says', () => {
    const parse = (o: object) =>
      McpServerReportSchema.parse({ ...server, ...o });
    expect(
      parse({ transport: 'http', url: 'https://h.example:8443/p?k=v#f' }).url,
    ).toBe('https://h.example:8443');
    expect(parse({ url: 'https://u:pw@h.example/x' }).url).toBeNull();
    expect(parse({ url: 'https://u@h.example/x' }).url).toBeNull();
    expect(parse({ url: 'not a url' }).url).toBeNull();
    expect(parse({ url: 'file:///etc/passwd' }).url).toBeNull();
    for (const command of [
      '/usr/bin/npx',
      'C:\\x\\npx.exe',
      'npx -y x',
      'sh -c "KEY=abc"',
    ])
      expect(parse({ command }).command).toBeNull();
    expect(parse({ command: 'npx' }).command).toBe('npx');
    for (const pkg of [
      'git+https://u:tok@github.com/o/r',
      'user:tok@host/x',
      'a b',
      'pkg@1.0.0',
    ])
      expect(parse({ package: pkg }).package).toBeNull();
    expect(parse({ package: '@scope/name' }).package).toBe('@scope/name');
    for (const version of ['1.0 beta', 'https://x', 'a@b', ''])
      expect(parse({ version }).version).toBeNull();
    expect(parse({ version: 'v1.2.3-rc.1' }).version).toBe('v1.2.3-rc.1');
    expect(
      parse({ envKeys: ['GOOD_1', 'bad key', 'A=b', '1X', 'ok'] }).envKeys,
    ).toEqual(['GOOD_1', 'ok']);
    expect(parse({ argCount: 3 })).not.toHaveProperty('args');
  });

  it('never fails the whole inventory because of one MCP entry', () => {
    const body = InventoryRequestSchema.parse({
      tools: [],
      mcpServers: [
        server,
        { ...server, name: 'long', package: 'p'.repeat(300) },
        { ...server, name: 'bad\nname' },
        { ...server, name: 'p214', package: 'p'.repeat(214) },
        'junk',
        null,
        42,
      ],
    });
    expect(parseMcpServers(body.mcpServers).map((s) => s.name)).toEqual([
      'fs',
      'p214',
    ]);
    expect(parseMcpServers(Array(500).fill(server))).toHaveLength(200);
  });

  it('replaces the device list, scoped to that host, and returns only new servers', async () => {
    const { client, ops } = fakeClient([
      { toolId: 'host.cursor', name: 'old' },
    ]);
    const fresh = await replaceHostMcpServers(
      client as never,
      'h-a',
      [
        McpServerReportSchema.parse(server),
        McpServerReportSchema.parse(server),
      ],
      new Date(),
    );
    expect(fresh).toEqual([{ toolId: 'host.cursor', name: 'fs', flags: [] }]);
    // one delete (everything of this host not reported) + one upsert (the duplicate is dropped)
    expect(ops).toHaveLength(2);
    expect(client.hostMcpServer.deleteMany).toHaveBeenCalledWith({
      where: {
        hostId: 'h-a',
        NOT: [expect.objectContaining({ toolId: 'host.cursor', name: 'fs' })],
      },
    });
    expect(JSON.stringify(ops)).not.toContain('"args"');
  });

  it('lists with flags computed now and marks a silent device stale', async () => {
    const client = {
      host: {
        findMany: vi.fn(() =>
          Promise.resolve([
            {
              id: 'h-a',
              hostname: 'pc',
              lastSeenAt: new Date(Date.now() - 3 * 3600_000),
              mcpServers: [
                {
                  id: '1',
                  toolId: 'host.cursor',
                  name: 'x',
                  transport: 'http',
                  command: null,
                  argCount: 0,
                  outsideHome: false,
                  url: 'http://example.org',
                  pkg: null,
                  pkgVersion: null,
                  envKeys: [],
                  firstSeenAt: new Date(),
                  lastSeenAt: new Date(),
                },
              ],
            },
          ]),
        ),
      },
    };
    const out = await listMcpServers(client as never);
    expect(out.servers[0]).toMatchObject({
      stale: true,
      flags: ['unknown_publisher', 'remote_no_tls'],
    });
  });
});
