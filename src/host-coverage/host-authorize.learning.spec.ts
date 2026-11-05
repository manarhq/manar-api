/* eslint-disable @typescript-eslint/no-unsafe-assignment -- expect matchers */
import { describe, expect, it, vi } from 'vitest';
import type { HostContext } from '../host-mtls/host-context';
import { HostAuthorizeService } from './host-authorize.service';

const host: HostContext = {
  hostId: 'h1',
  tenantId: 't1',
  machineId: 'm',
  ownerSubject: 'owner',
  status: 'APPROVED',
};

function make(learns: boolean) {
  const open = vi.fn(() =>
    Promise.resolve({ id: 'a1', expiresAt: new Date() }),
  );
  type Fn = (...a: unknown[]) => Promise<unknown>;
  const serve = vi.fn<Fn>().mockResolvedValue(learns);
  const audit = {
    recordSafely: vi.fn<Fn>().mockResolvedValue({ id: 'e' }),
  };
  const client = {
    approvalAllowGrant: {
      findFirst: () => Promise.resolve(null),
      findMany: () => Promise.resolve([]),
    },
  };
  const svc = new HostAuthorizeService(
    { getClient: () => Promise.resolve(client) } as never,
    { checkAll: () => Promise.resolve({ killed: false }) } as never,
    { evaluate: () => Promise.resolve({ effect: 'ALLOW' }) } as never,
    audit as never,
    { open },
    { serve } as never,
  );
  return { svc, open, serve, audit };
}
const edit = {
  toolId: 'host.cursor',
  actionId: 'edit',
  resource: '/home/sara/proj/a.ts',
};

describe('learning mode on /host/v1/authorize', () => {
  it('serves ALLOW, opens nothing, and the audit record keeps the real outcome', async () => {
    const w = make(true);
    const r = await w.svc.authorize(host, edit);
    expect(r).toMatchObject({
      decision: 'ALLOW',
      reason: 'learning_would_ask',
    });
    expect(w.open).not.toHaveBeenCalled();
    expect(w.audit.recordSafely).toHaveBeenCalledWith(
      expect.anything(),
      't1',
      expect.objectContaining({
        eventType: 'host.action_decided',
        data: expect.objectContaining({
          decision: 'APPROVAL_REQUIRED',
          reason: 'risk_ceiling_exceeded',
          learning: true,
          served: 'ALLOW',
          approvalId: null,
        }),
      }),
    );
  });
  it('asks as usual when the device is not learning', async () => {
    const w = make(false);
    const r = await w.svc.authorize(host, edit);
    expect(r).toMatchObject({
      decision: 'APPROVAL_REQUIRED',
      approvalId: 'a1',
    });
    expect(w.open).toHaveBeenCalled();
    const rec = w.audit.recordSafely.mock.calls.at(-1)![2] as {
      data: Record<string, unknown>;
    };
    expect(rec.data).not.toHaveProperty('learning');
  });
  it('is asked only for asks, with the catalogue score', async () => {
    const w = make(true);
    await w.svc.authorize(host, { ...edit, actionId: 'read' });
    expect(w.serve).not.toHaveBeenCalled();
    await w.svc.authorize(host, edit);
    expect(w.serve.mock.calls[0]![4]).toMatchObject({
      riskScore: 35,
      askKey: 'ceiling',
    });
  });
  it('a failing learning check means the normal prompt', async () => {
    const w = make(true);
    w.serve.mockRejectedValueOnce(new Error('db'));
    expect((await w.svc.authorize(host, edit)).decision).toBe(
      'APPROVAL_REQUIRED',
    );
  });
});
