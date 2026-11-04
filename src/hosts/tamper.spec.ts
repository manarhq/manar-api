import { describe, expect, it, vi } from 'vitest';
import { HostToolsService } from '../host-coverage/host-tools.service';
import { HostEventsBatchSchema } from '../secrets/secrets.validation';
import { TAMPER_EVENT_TYPES, TAMPER_WINDOW_MS, latestTamper } from './tamper';

const at = new Date('2026-11-03T08:00:00Z');

describe('device tamper reports', () => {
  it('the events endpoint accepts every kind the device sends, and no other', () => {
    for (const type of TAMPER_EVENT_TYPES) {
      const r = HostEventsBatchSchema.safeParse({
        events: [
          {
            type,
            toolId: 'host.claude-code',
            process: 'claude',
            maskedPath: '~/app/.claude/settings.local.json',
            blocked: false,
            at: at.toISOString(),
          },
        ],
      });
      expect(r.success, type).toBe(true);
    }
    expect(
      HostEventsBatchSchema.safeParse({
        events: [{ type: 'protect.tamper.other', at: at.toISOString() }],
      }).success,
    ).toBe(false);
  });

  it('takes the latest report per device within the window', async () => {
    const findMany = vi.fn(() =>
      Promise.resolve([
        {
          hostId: 'h1',
          type: 'protect.tamper.hooks_disabled',
          toolId: 'host.claude-code',
          maskedPath: '~/app/.claude/settings.json',
          at,
        },
      ]),
    );
    const now = at.getTime() + 1000;
    const m = await latestTamper(
      { secretEvent: { findMany } } as never,
      ['h1', 'h2'],
      now,
    );
    expect(m.get('h1')).toEqual({
      at: at.toISOString(),
      kind: 'protect.tamper.hooks_disabled',
      toolId: 'host.claude-code',
      maskedPath: '~/app/.claude/settings.json',
    });
    expect(m.has('h2')).toBe(false);
    const q = (findMany.mock.calls[0] as unknown as [Record<string, never>])[0];
    expect(q).toMatchObject({
      where: {
        hostId: { in: ['h1', 'h2'] },
        type: { in: [...TAMPER_EVENT_TYPES] },
        at: { gte: new Date(now - TAMPER_WINDOW_MS) },
      },
      distinct: ['hostId'],
    });
    // No devices, no query.
    findMany.mockClear();
    await latestTamper({ secretEvent: { findMany } } as never, []);
    expect(findMany).not.toHaveBeenCalled();
  });

  it('AI tools shows the device as tampered and the tool it concerns as observed-only', async () => {
    const recent = new Date(Date.now() - 60_000);
    const client = {
      host: {
        findMany: vi.fn(() =>
          Promise.resolve([
            {
              id: 'h1',
              hostname: 'laptop',
              os: 'linux',
              status: 'APPROVED',
              lastSeenAt: new Date(),
              tools: [
                {
                  toolId: 'host.claude-code',
                  name: 'Claude Code',
                  protected: true,
                  protectMode: 'hook',
                  desiredProtection: true,
                  changes: [],
                },
                {
                  toolId: 'host.cursor',
                  name: 'Cursor',
                  protected: true,
                  protectMode: 'hook',
                  desiredProtection: true,
                  changes: [],
                },
              ],
            },
          ]),
        ),
      },
      secretEvent: {
        findMany: vi.fn(() =>
          Promise.resolve([
            {
              hostId: 'h1',
              type: 'protect.tamper.settings_flag',
              toolId: 'host.claude-code',
              maskedPath: null,
              at: recent,
            },
          ]),
        ),
      },
    };
    const svc = new HostToolsService(
      { getClient: () => Promise.resolve(client) } as never,
      {} as never,
    );
    const { devices } = await svc.list('t');
    expect(devices[0]!.tamper).toMatchObject({
      kind: 'protect.tamper.settings_flag',
      toolId: 'host.claude-code',
    });
    const label = (id: string) =>
      devices[0]!.tools.find((t) => t.toolId === id)!.enforcement;
    expect(label('host.claude-code')).toBe('observed-only');
    expect(label('host.cursor')).toBe('governed');
  });
});
