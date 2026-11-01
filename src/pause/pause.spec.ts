import { describe, expect, it, vi } from 'vitest';
import { KillSwitchService } from '../kill-switches/kill-switch.service';
import { PauseService } from './pause.service';
import { isWorkspacePaused } from './pause-state';

function fakeClient(initial = false) {
  let row: {
    paused: boolean;
    pausedBy: string | null;
    pausedAt: Date | null;
  } | null = initial
    ? { paused: true, pausedBy: 'u0', pausedAt: new Date() }
    : null;
  return {
    workspacePause: {
      findUnique: vi.fn(() => Promise.resolve(row)),
      upsert: vi.fn(
        ({ create, update }: { create: object; update: object }) => {
          row = (row ? { ...row, ...update } : { ...create }) as typeof row;
          return Promise.resolve(row);
        },
      ),
    },
    killSwitch: { findFirst: vi.fn(() => Promise.resolve(null)) },
    agentQuarantine: { findFirst: vi.fn(() => Promise.resolve(null)) },
  };
}

function service(client: ReturnType<typeof fakeClient>) {
  const audit = {
    recordSafely: vi.fn<(c: unknown, t: string, e: object) => Promise<boolean>>(
      () => Promise.resolve(true),
    ),
  };
  const tenants = { getClient: vi.fn(() => Promise.resolve(client)) };
  return { audit, svc: new PauseService(tenants as any, audit as any) };
}

describe('Pause all AI', () => {
  it('is off until pressed, then on, then off, and logs only changes', async () => {
    const c = fakeClient();
    const { svc, audit } = service(c);
    expect(await svc.get('t1')).toEqual({
      paused: false,
      pausedAt: null,
      pausedBy: null,
    });
    const on = await svc.set('t1', true, 'alice');
    expect(on.paused).toBe(true);
    expect(on.pausedBy).toBe('alice');
    await svc.set('t1', true, 'alice'); // second press: no second event
    expect(audit.recordSafely).toHaveBeenCalledTimes(1);
    expect(audit.recordSafely.mock.calls[0]?.[2]).toMatchObject({
      eventType: 'workspace.ai.paused',
    });
    const off = await svc.set('t1', false, 'bob');
    expect(off).toEqual({ paused: false, pausedAt: null, pausedBy: null });
    expect(audit.recordSafely.mock.calls[1]?.[2]).toMatchObject({
      eventType: 'workspace.ai.resumed',
    });
    expect(await svc.isPaused('t1')).toBe(false);
  });

  it('every authorize path is denied with reason paused (kill-switch check)', async () => {
    const c = fakeClient(true);
    const ks = new KillSwitchService(
      { recordSafely: vi.fn() } as any,
      { isActive: () => Promise.resolve(false) } as any,
    );
    const r = await ks.checkAll(c as any, 't1', {
      agentId: 'a',
      toolId: 'host.cursor',
    });
    expect(r).toEqual({ killed: true, scope: 'PAUSE', reason: 'paused' });
  });

  it('fails closed when the pause row cannot be read', async () => {
    const c = fakeClient();
    c.workspacePause.findUnique.mockRejectedValueOnce(new Error('db down'));
    await expect(isWorkspacePaused(c as any)).rejects.toThrow('db down');
  });
});
