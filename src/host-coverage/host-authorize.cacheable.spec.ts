import { describe, expect, it, vi } from 'vitest';
import type { HostContext } from '../host-mtls/host-context';
import { effectivePolicyVersion } from '../policy/policy-engine.service';
import { HostConfigController } from '../host-mtls/host-config.controller';
import { HostAuthorizeService } from './host-authorize.service';

const host: HostContext = {
  hostId: 'h1',
  tenantId: 't1',
  machineId: 'm',
  ownerSubject: 'owner',
  status: 'APPROVED',
};
const read = { toolId: 'host.cursor', actionId: 'read', resource: '/a' };
const shell = { toolId: 'host.cursor', actionId: 'shell', resource: 'ls' };

function make(o: {
  status?: HostContext['status'];
  grant?: boolean;
  block?: boolean;
  killed?: boolean;
  policy?: unknown;
  throws?: boolean;
  auditFails?: boolean;
}) {
  const grants = {
    findFirst: vi.fn((a?: { where?: { effect?: string } }) =>
      Promise.resolve(
        a?.where?.effect === 'BLOCK'
          ? o.block
            ? { id: 'b1' }
            : null
          : o.grant
            ? { id: 'g1', expiresAt: new Date() }
            : null,
      ),
    ),
    update: vi.fn(() => Promise.resolve({})),
  };
  const svc = new HostAuthorizeService(
    {
      getClient: () =>
        o.throws
          ? Promise.reject(new Error('db'))
          : Promise.resolve({ approvalAllowGrant: grants }),
    } as never,
    {
      checkAll: () =>
        Promise.resolve(o.killed ? { killed: true } : { killed: false }),
    } as never,
    {
      evaluate: () => Promise.resolve(o.policy ?? { effect: 'ALLOW' }),
    } as never,
    {
      recordSafely: () => Promise.resolve(o.auditFails ? null : { id: 'e' }),
    } as never,
    {
      open: () => Promise.resolve({ id: 'a1', expiresAt: new Date() }),
    },
  );
  return (req = read) =>
    svc.authorize({ ...host, status: o.status ?? 'APPROVED' }, req);
}

describe('host authorize always sets an explicit boolean cacheable', () => {
  const paths: Array<
    [string, Parameters<typeof make>[0], typeof read, boolean]
  > = [
    ['plain policy ALLOW', {}, read, true],
    ['host not approved', { status: 'PENDING' }, read, false],
    ['unknown tool', {}, { ...read, toolId: 'nope' }, false],
    ['unknown action', {}, { ...read, actionId: 'NOPE' }, false],
    ['kill switch', { killed: true }, read, false],
    ['revoked after use', { block: true }, read, false],
    ['policy DENY', { policy: { effect: 'DENY' } }, read, false],
    [
      'policy APPROVAL_REQUIRED',
      { policy: { effect: 'APPROVAL_REQUIRED' } },
      read,
      false,
    ],
    ['approval required by risk ceiling', {}, shell, false],
    [
      'grant on policy approval',
      { grant: true, policy: { effect: 'APPROVAL_REQUIRED' } },
      read,
      false,
    ],
    ['grant on risk ceiling', { grant: true }, shell, false],
    ['dependency failure', { throws: true }, read, false],
    ['audit not recorded', { auditFails: true }, read, false],
  ];
  it.each(paths)('%s', async (_n, opts, req, expected) => {
    const r = await make(opts)(req);
    expect(r.cacheable).toBe(expected);
    expect(typeof r.cacheable).toBe('boolean');
  });
});

describe('effectivePolicyVersion', () => {
  const client = (rows: Array<{ id: string; policyId: string }>) =>
    ({ policyVersion: { findMany: () => Promise.resolve(rows) } }) as never;
  it('is stable, changes when the latest version changes, and has no content', async () => {
    const a = await effectivePolicyVersion(
      client([
        { id: 'v2', policyId: 'p1' },
        { id: 'v1', policyId: 'p1' },
      ]),
    );
    const same = await effectivePolicyVersion(
      client([{ id: 'v2', policyId: 'p1' }]),
    );
    const next = await effectivePolicyVersion(
      client([{ id: 'v3', policyId: 'p1' }]),
    );
    expect(a).toBe(same);
    expect(next).not.toBe(a);
    expect(a).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe('config poll policyVersion', () => {
  const ctrl = (getClient: () => Promise<unknown>) =>
    Object.assign(Object.create(HostConfigController.prototype), {
      tenants: { getClient },
      logger: { warn: vi.fn() },
    }) as unknown as { policyVersion(h: HostContext): Promise<string | null> };
  const db = {
    policyVersion: {
      findMany: () => Promise.resolve([{ id: 'v1', policyId: 'p1' }]),
    },
  };
  it('is the tenant version for an approved device, null when unapproved or unreadable', async () => {
    expect(await ctrl(() => Promise.resolve(db)).policyVersion(host)).toMatch(
      /^[0-9a-f]{16}$/,
    );
    expect(
      await ctrl(() => Promise.resolve(db)).policyVersion({
        ...host,
        status: 'PENDING',
      }),
    ).toBeNull();
    expect(
      await ctrl(() => Promise.reject(new Error('db'))).policyVersion(host),
    ).toBeNull();
  });
});
