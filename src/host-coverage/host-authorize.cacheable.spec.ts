import { describe, expect, it, vi } from 'vitest';
import type { HostContext } from '../host-mtls/host-context';
import { effectivePolicyVersion } from '../policy/effective-policy-version';
import { HostConfigController } from '../host-mtls/host-config.controller';
import { ServiceUnavailableException } from '@nestjs/common';
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

const base = () => ({
  policies: [{ id: 'v1', policyId: 'p1' }],
  switches: [] as Array<{ id: string }>,
  pause: { paused: false } as { paused: boolean } | null,
  quarantine: null as { id: string } | null,
  memberships: [] as Array<{ groupId: string }>,
  links: [] as Array<{ aiSystemId: string }>,
  systems: [] as Array<{ id: string; lifecycleState: string }>,
  blocks: [] as Array<{ id: string }>,
  actions: [{ id: 'a1', classification: 'INTERNAL', riskBaseScore: 10 }],
});
type State = ReturnType<typeof base>;
const db = (s: State) =>
  ({
    policyVersion: { findMany: () => Promise.resolve(s.policies) },
    killSwitch: { findMany: () => Promise.resolve(s.switches) },
    workspacePause: { findUnique: () => Promise.resolve(s.pause) },
    agentQuarantine: { findFirst: () => Promise.resolve(s.quarantine) },
    agentGroupMembership: { findMany: () => Promise.resolve(s.memberships) },
    aiSystemAgentLink: { findMany: () => Promise.resolve(s.links) },
    aiSystem: { findMany: () => Promise.resolve(s.systems) },
    approvalAllowGrant: { findMany: () => Promise.resolve(s.blocks) },
    toolAction: { findMany: () => Promise.resolve(s.actions) },
  }) as never;
const ver = (s: State, platform = false) =>
  effectivePolicyVersion(db(s), 'h1', platform);

describe('effectivePolicyVersion', () => {
  it('is stable and opaque', async () => {
    const v = await ver(base());
    expect(v).toBe(await ver(base()));
    expect(v).toMatch(/^[0-9a-f]{16}$/);
  });

  const flips: Array<[string, (s: State) => void]> = [
    [
      'a newer published policy version',
      (s) => (s.policies = [{ id: 'v2', policyId: 'p1' }]),
    ],
    ['an active kill switch', (s) => s.switches.push({ id: 'k1' })],
    ['pause', (s) => (s.pause = { paused: true })],
    ['host quarantine', (s) => (s.quarantine = { id: 'q1' })],
    ['a group membership', (s) => s.memberships.push({ groupId: 'g1' })],
    [
      'an AI system suspension',
      (s) => {
        s.links.push({ aiSystemId: 's1' });
        s.systems.push({ id: 's1', lifecycleState: 'SUSPENDED' });
      },
    ],
    ['a live revoked-after-use block', (s) => s.blocks.push({ id: 'b1' })],
    [
      'a tool classification',
      (s) => (s.actions[0]!.classification = 'RESTRICTED'),
    ],
    ['a tool risk score', (s) => (s.actions[0]!.riskBaseScore = 90)],
  ];
  it.each(flips)('changes when %s changes', async (_n, mutate) => {
    const s = base();
    const before = await ver(s);
    mutate(s);
    expect(await ver(s)).not.toBe(before);
  });

  it('changes when the platform kill switch turns on', async () => {
    expect(await ver(base(), true)).not.toBe(await ver(base(), false));
  });
});

describe('config poll policyVersion', () => {
  const ctrl = (getClient: () => Promise<unknown>) =>
    Object.assign(Object.create(HostConfigController.prototype), {
      tenants: { getClient },
      platformKill: { isActive: () => Promise.resolve(false) },
      logger: { warn: vi.fn(), error: vi.fn() },
    }) as unknown as { policyVersion(h: HostContext): Promise<string> };

  it('is the opaque token for an approved device', async () => {
    expect(
      await ctrl(() => Promise.resolve(db(base()))).policyVersion(host),
    ).toMatch(/^[0-9a-f]{16}$/);
  });
  it.each(['PENDING', 'REVOKED', 'SUSPENDED', 'QUARANTINED'])(
    'is a fixed revoked sentinel for a %s device',
    async (status) => {
      expect(
        await ctrl(() => Promise.resolve(db(base()))).policyVersion({
          ...host,
          status: status as HostContext['status'],
        }),
      ).toBe(`revoked:${status}`);
    },
  );
  it('fails the poll with 503 when the read fails', async () => {
    await expect(
      ctrl(() => Promise.reject(new Error('db'))).policyVersion(host),
    ).rejects.toBeInstanceOf(ServiceUnavailableException);
  });
});
