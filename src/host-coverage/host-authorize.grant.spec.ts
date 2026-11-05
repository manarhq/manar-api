/* eslint-disable @typescript-eslint/no-unsafe-assignment -- expect matchers */
import { describe, expect, it, vi } from 'vitest';
import type { HostContext } from '../host-mtls/host-context';
import { HostAuthorizeService, policyAskKey } from './host-authorize.service';

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
  /** The ask the scoped grants were made for. */
  grantAsk?: string;
  /** An 8-hour grant's own ask (a grant without one answers any ask). */
  grantKey?: string | null;
}) {
  const grants = {
    findFirst: vi.fn((args?: { where?: { effect?: string } }) =>
      Promise.resolve(
        args?.where?.effect === 'BLOCK'
          ? opts.block
            ? { id: 'b1' }
            : null
          : opts.grant
            ? { id: 'g1', expiresAt: new Date(), askKey: opts.grantKey ?? null }
            : null,
      ),
    ),
    findMany: vi.fn((args?: { where?: { askKey?: string } }) =>
      Promise.resolve(
        (opts.patterns ?? [])
          .filter((_, i) => i >= 0)
          .filter(() => args?.where?.askKey === (opts.grantAsk ?? 'ceiling'))
          .map((p) => ({
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
const shell = {
  toolId: 'host.cursor',
  actionId: 'SHELL',
  resource: 'make deploy',
};

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
          resource: 'make deploy',
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
      const w = make({
        patterns: ['/home/sara/proj/src/*'],
        policy: ask,
        grantAsk: policyAskKey({
          policyVersionId: undefined,
          matchedRule: undefined,
        }),
      });
      const r = await w.svc.authorize(host, edit('/home/sara/proj/src/a.ts'));
      expect(r).toMatchObject({ decision: 'ALLOW', grantId: 'g2' });
    });
    it('still asks outside the folder, for secrets and for ..', async () => {
      const w = make({
        patterns: ['/home/sara/proj/src/*'],
        policy: ask,
        grantAsk: policyAskKey({
          policyVersionId: undefined,
          matchedRule: undefined,
        }),
      });
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

  describe('a grant answers only the ask it was made for', () => {
    const edit = {
      toolId: 'host.cursor',
      actionId: 'edit',
      resource: '/home/sara/proj/src/a.ts',
    };
    const rule = {
      effect: 'APPROVAL_REQUIRED',
      policyVersionId: 'v1',
      matchedRule: { toolId: '*', actionId: 'edit', resourcePattern: '*' },
    };
    it('a scope made for the risk ceiling does not answer a policy rule', async () => {
      const w = make({ patterns: ['/home/sara/proj/src/*'], policy: rule });
      const r = await w.svc.authorize(host, edit);
      expect(r.decision).toBe('APPROVAL_REQUIRED');
      expect(r.askKey).toMatch(/^p:[0-9a-f]{24}$/);
    });
    it('a scope made for this rule answers it, republishing the policy does not', async () => {
      const first = await make({ policy: rule }).svc.authorize(host, edit);
      const mine = make({
        patterns: ['/home/sara/proj/src/*'],
        grantAsk: first.askKey,
        policy: rule,
      });
      expect((await mine.svc.authorize(host, edit)).decision).toBe('ALLOW');
      const republished = make({
        patterns: ['/home/sara/proj/src/*'],
        grantAsk: first.askKey,
        policy: { ...rule, policyVersionId: 'v2' },
      });
      expect((await republished.svc.authorize(host, edit)).decision).toBe(
        'APPROVAL_REQUIRED',
      );
    });
    it('an 8-hour grant made for one ask does not answer another; an older one still does', async () => {
      const shell = {
        toolId: 'host.cursor',
        actionId: 'SHELL',
        resource: 'make deploy',
      };
      expect(
        (
          await make({ grant: true, grantKey: 'p:other' }).svc.authorize(
            host,
            shell,
          )
        ).decision,
      ).toBe('APPROVAL_REQUIRED');
      expect(
        (
          await make({ grant: true, grantKey: 'ceiling' }).svc.authorize(
            host,
            shell,
          )
        ).decision,
      ).toBe('ALLOW');
      expect(
        (await make({ grant: true, grantKey: null }).svc.authorize(host, shell))
          .decision,
      ).toBe('ALLOW');
    });
    it('what a grant lets through is never cacheable by the device', async () => {
      const w = make({ patterns: ['/home/sara/proj/src/*'] });
      expect(await w.svc.authorize(host, edit)).toMatchObject({
        decision: 'ALLOW',
        cacheable: false,
      });
      const exact = make({ grant: true });
      expect(
        await exact.svc.authorize(host, {
          toolId: 'host.cursor',
          actionId: 'SHELL',
          resource: 'make deploy',
        }),
      ).toMatchObject({ decision: 'ALLOW', cacheable: false });
    });
  });
});

describe('clearly read-only shell commands score 30 (below high risk, above the ceiling)', () => {
  const sh = (resource: string) => ({
    toolId: 'host.claude-code',
    actionId: 'shell',
    resource,
  });
  it('with no rule they still ask, but are not high risk; test and build runs stay at 70', async () => {
    const w = make({});
    expect(await w.svc.authorize(host, sh('ls -la src'))).toMatchObject({
      decision: 'APPROVAL_REQUIRED',
      reason: 'risk_ceiling_exceeded',
      riskScore: 30,
    });
    for (const c of ['pnpm test', 'cargo test', 'go test ./...', 'pytest'])
      expect(await w.svc.authorize(host, sh(c))).toMatchObject({
        decision: 'APPROVAL_REQUIRED',
        riskScore: 70,
      });
  });
  it('a workspace whose preset allows the rest still allows them', async () => {
    const w = make({ policy: { effect: 'ALLOW', matchedRule: {} } });
    expect(await w.svc.authorize(host, sh('ls -la src'))).toMatchObject({
      decision: 'ALLOW',
      riskScore: 30,
    });
  });
  it('bypass attempts keep the catalogue score of 70', async () => {
    const w = make({});
    for (const c of [
      'ls; rm -rf ~',
      'git status',
      'ls $(cat ~/.ssh/id_rsa)',
      '/bin/ls',
      'cat .env',
      'grep -r password',
      'rg --hidden key src',
    ])
      expect(await w.svc.authorize(host, sh(c))).toMatchObject({
        decision: 'APPROVAL_REQUIRED',
        riskScore: 70,
      });
  });
  it('a policy that asks still asks', async () => {
    const w = make({ policy: { effect: 'APPROVAL_REQUIRED' } });
    expect((await w.svc.authorize(host, sh('ls -la src'))).decision).toBe(
      'APPROVAL_REQUIRED',
    );
  });
});
