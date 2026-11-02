import { describe, expect, it, vi } from 'vitest';
import { HostToolsService, InventoryRequestSchema } from './host-tools.service';
import {
  EXPECTED_MODULES,
  protectionStatus,
  type ProtectionHostRow,
} from './protection-status';

const now = new Date('2026-11-03T12:00:00Z');
const STALE = 30 * 60 * 1000;
const allModules = Object.fromEntries(
  EXPECTED_MODULES.map((m) => [m, { state: 'ok' }]),
);

function host(over: Partial<ProtectionHostRow> = {}): ProtectionHostRow {
  return {
    id: 'h1',
    hostname: 'laptop',
    os: 'linux',
    status: 'APPROVED',
    lastSeenAt: new Date(now.getTime() - 60_000),
    modules: allModules,
    tools: [
      {
        toolId: 'host.claude-code',
        name: 'Claude Code',
        protected: true,
        desiredProtection: true,
      },
    ],
    ...over,
  };
}

const codes = (h: ProtectionHostRow[]) =>
  protectionStatus(h, now, STALE).problems.map((p) => p.code);

describe('protectionStatus', () => {
  it('is all protected for an approved, fresh device with every tool protected and every module up', () => {
    const r = protectionStatus([host()], now, STALE);
    expect(r.ok).toBe(true);
    expect(r.problems).toEqual([]);
    expect(r.devices[0]).toMatchObject({
      online: true,
      toolsProtected: 1,
      toolsTotal: 1,
    });
  });

  it('says to add a device when there is none', () => {
    const r = protectionStatus([], now, STALE);
    expect(r.ok).toBe(false);
    expect(r.problems).toEqual([{ code: 'no_device' }]);
  });

  it('reports a pending device once, without judging its tools', () => {
    expect(
      codes([host({ status: 'PENDING', lastSeenAt: null, modules: null })]),
    ).toEqual(['device_pending']);
  });

  it('never judges tools or modules from a stale device', () => {
    const stale = host({
      lastSeenAt: new Date(now.getTime() - STALE - 1),
      tools: [
        {
          toolId: 'host.cursor',
          name: 'Cursor',
          protected: false,
          desiredProtection: true,
        },
      ],
      modules: { jail: { state: 'problem' } },
    });
    expect(codes([stale])).toEqual(['device_offline']);
    expect(codes([host({ lastSeenAt: null })])).toEqual([
      'device_never_synced',
    ]);
  });

  it('tells apart a tool switched off, one the device could not protect, and one Manar can only see', () => {
    const r = protectionStatus(
      [
        host({
          tools: [
            {
              toolId: 'host.claude-code',
              name: 'Claude Code',
              protected: false,
              desiredProtection: false,
            },
            {
              toolId: 'host.cursor',
              name: 'Cursor',
              protected: false,
              desiredProtection: true,
            },
            {
              toolId: 'host.chatgpt-desktop',
              name: 'ChatGPT desktop',
              protected: false,
              desiredProtection: true,
            },
          ],
        }),
      ],
      now,
      STALE,
    );
    expect(r.problems.map((p) => [p.code, p.toolName])).toEqual([
      ['tool_off', 'Claude Code'],
      ['tool_not_applied', 'Cursor'],
      ['tool_seen_only', 'ChatGPT desktop'],
    ]);
    expect(r.problems[0]).toMatchObject({
      hostId: 'h1',
      hostname: 'laptop',
      toolId: 'host.claude-code',
    });
  });

  it('reports a module that stopped and one that is missing, but not an older device that reports none', () => {
    const noDoor = { ...allModules };
    delete noDoor.door;
    expect(
      codes([host({ modules: { ...noDoor, jail: { state: 'problem' } } })]),
    ).toEqual(['module_down', 'module_missing']);
    expect(codes([host({ modules: null })])).toEqual([]);
  });

  it('ignores devices that are neither pending nor approved', () => {
    expect(codes([host({ status: 'REVOKED', lastSeenAt: null })])).toEqual([]);
  });
});

describe('inventory modules', () => {
  it('accepts module states and refuses bad names and states', () => {
    const ok = InventoryRequestSchema.safeParse({
      tools: [],
      modules: {
        jail: { state: 'ok' },
        'secrets-watch': { state: 'problem', detail: 'x' },
      },
    });
    expect(ok.success).toBe(true);
    expect(
      InventoryRequestSchema.safeParse({
        tools: [],
        modules: { Jail: { state: 'ok' } },
      }).success,
    ).toBe(false);
    expect(
      InventoryRequestSchema.safeParse({
        tools: [],
        modules: { jail: { state: 'great' } },
      }).success,
    ).toBe(false);
    expect(InventoryRequestSchema.safeParse({ tools: [] }).success).toBe(true);
  });
});

describe('HostToolsService modules and protection', () => {
  function svc() {
    const client = {
      tool: { upsert: vi.fn(() => Promise.resolve({ id: 'x' })) },
      toolAction: { upsert: vi.fn(() => Promise.resolve({})) },
      hostTool: {
        findMany: vi.fn(() => Promise.resolve([])),
        upsert: vi.fn(() => Promise.resolve({})),
        updateMany: vi.fn(() => Promise.resolve({})),
      },
      host: {
        update: vi.fn((arg: unknown) => Promise.resolve(arg && {})),
        findMany: vi.fn((arg: unknown) =>
          Promise.resolve(arg && ([] as unknown[])),
        ),
      },
    };
    const tenants = { getClient: vi.fn(() => Promise.resolve(client)) };
    const audit = { recordSafely: vi.fn(() => Promise.resolve({})) };
    return {
      client,
      s: new HostToolsService(tenants as never, audit as never),
    };
  }
  const h = { hostId: 'h1', tenantId: 't1' };

  it('stores the modules a device reports, and leaves them alone when an older device sends none', async () => {
    const { client, s } = svc();
    await s.report(h, { tools: [], modules: { jail: { state: 'ok' } } });
    expect(client.host.update.mock.calls[0]?.[0]).toMatchObject({
      data: { modules: { jail: { state: 'ok' } } },
    });
    await s.report(h, { tools: [] });
    expect(client.host.update.mock.calls[1]?.[0]).not.toHaveProperty(
      'data.modules',
    );
  });

  it('answers protection from pending and approved devices only', async () => {
    const { client, s } = svc();
    const r = await s.protection('t1');
    expect(r.problems).toEqual([{ code: 'no_device' }]);
    expect(client.host.findMany.mock.calls[0]?.[0]).toMatchObject({
      where: { status: { in: ['PENDING', 'APPROVED'] } },
    });
  });
});
