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

function make(opts: {
  grant?: boolean;
  block?: boolean;
  policy?: unknown;
  patterns?: string[];
}) {
  const grants = {
    findFirst: vi.fn((args?: { where?: { effect?: string } }) =>
      Promise.resolve(
        args?.where?.effect === 'BLOCK'
          ? opts.block
            ? { id: 'b1' }
            : null
          : opts.grant
            ? { id: 'g1', expiresAt: new Date() }
            : null,
      ),
    ),
    findMany: vi.fn(() =>
      Promise.resolve(
        (opts.patterns ?? []).map((p) => ({
          id: 'g2',
          expiresAt: new Date(),
          resourcePattern: p,
        })),
      ),
    ),
    update: vi.fn(() => Promise.resolve({})),
  };
  const tenants = {
    getClient: () => Promise.resolve({ approvalAllowGrant: grants }),
  };
  const audit = { recordSafely: vi.fn(() => Promise.resolve({ id: 'e' })) };
  const svc = new HostAuthorizeService(
    tenants as never,
    { checkAll: () => Promise.resolve({ killed: false }) } as never,
    {
      evaluate: () => Promise.resolve(opts.policy ?? { effect: 'ALLOW' }),
    } as never,
    audit as never,
  );
  return { svc, grants, audit };
}
const shell = { toolId: 'host.cursor', actionId: 'SHELL', resource: 'ls' };

describe('8-hour grants on /host/v1/authorize', () => {
  it('asks without a grant, allows with one and audits the use', async () => {
    expect((await make({}).svc.authorize(host, shell)).decision).toBe(
      'APPROVAL_REQUIRED',
    );
    const w = make({ grant: true });
    const r = await w.svc.authorize(host, shell);
    expect(r.decision).toBe('ALLOW');
    expect(w.grants.update).toHaveBeenCalled();
    expect(w.audit.recordSafely).toHaveBeenCalledWith(
      expect.anything(),
      't1',
      expect.objectContaining({ eventType: 'approval.grant.used' }),
    );
  });

  it('looks the grant up for this host, with the lower-cased action and the exact resource', async () => {
    const w = make({ grant: true });
    await w.svc.authorize(host, shell);
    expect(w.grants.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          hostId: 'h1',
          toolId: 'host.cursor',
          actionId: 'shell',
          resource: 'ls',
        }),
      }),
    );
  });

  it('never overrides a policy DENY', async () => {
    const w = make({ grant: true, policy: { effect: 'DENY' } });
    expect((await w.svc.authorize(host, shell)).decision).toBe('DENY');
  });

  it('a block from a revoked-after-use approval denies, even with a live grant', async () => {
    const w = make({ grant: true, block: true });
    const r = await w.svc.authorize(host, shell);
    expect(r).toMatchObject({ decision: 'DENY', reason: 'revoked_after_use' });
  });

  it('a failing grant lookup denies', async () => {
    const w = make({});
    w.grants.findFirst.mockRejectedValueOnce(new Error('db'));
    expect((await w.svc.authorize(host, shell)).decision).toBe('DENY');
  });

  describe('"always allow this here" scopes', () => {
    const edit = (resource: string) => ({
      toolId: 'host.cursor',
      actionId: 'edit',
      resource,
    });
    const ask = { effect: 'APPROVAL_REQUIRED' };
    it('allows inside the folder and audits the use', async () => {
      const w = make({ patterns: ['/home/sara/proj/src/*'], policy: ask });
      const r = await w.svc.authorize(host, edit('/home/sara/proj/src/a.ts'));
      expect(r).toMatchObject({ decision: 'ALLOW', grantId: 'g2' });
    });
    it('still asks outside the folder, for secrets and for ..', async () => {
      const w = make({ patterns: ['/home/sara/proj/src/*'], policy: ask });
      for (const res of [
        '/home/sara/proj/other/a.ts',
        '/home/sara/proj/src/.env',
        '/home/sara/proj/src/../../x/a.ts',
      ])
        expect((await w.svc.authorize(host, edit(res))).decision).toBe(
          'APPROVAL_REQUIRED',
        );
    });
    it('is not looked up when nothing asks', async () => {
      const w = make({
        patterns: ['/home/sara/proj/src/*'],
        policy: { effect: 'ALLOW', matchedRule: {} },
      });
      await w.svc.authorize(host, edit('/home/sara/proj/src/a.ts'));
      expect(w.grants.findMany).not.toHaveBeenCalled();
    });
  });
});
