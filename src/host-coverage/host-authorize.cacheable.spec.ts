import { describe, expect, it, vi } from 'vitest';
import type { HostContext } from '../host-mtls/host-context';
import {
  HOST_RULES_VERSION,
  hostPolicyState,
} from '../policy/effective-policy-version';
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

type Sw = { id: string; scope: string; targetId: string | null };
const rule = (toolId: string, actionId: string, effect: string) => ({
  rules: [{ toolId, actionId, resourcePattern: '*', effect }],
});
const base = () => ({
  policies: [{ id: 'v1', content: rule('*', 'shell', 'ALLOW') }] as Array<{
    id: string;
    content: unknown;
  }>,
  switches: [] as Sw[],
  pause: { paused: false } as { paused: boolean } | null,
  blocks: [] as Array<{ id: string }>,
  actions: [{ id: 'a1', classification: 'INTERNAL', riskBaseScore: 10 }],
});
type State = ReturnType<typeof base>;
// Applies the same OR filter the real query sends, so an unrelated switch really is excluded.
const matchSwitch = (
  sw: Sw,
  or: Array<{ scope: string; targetId?: string | { in: string[] } }>,
) =>
  or.some(
    (c) =>
      c.scope === sw.scope &&
      (c.targetId === undefined ||
        (typeof c.targetId === 'string'
          ? c.targetId === sw.targetId
          : c.targetId.in.includes(sw.targetId ?? ''))),
  );
const db = (s: State) =>
  ({
    tool: { findMany: () => Promise.resolve([{ id: 't-cursor' }]) },
    policyVersion: { findMany: () => Promise.resolve(s.policies) },
    killSwitch: {
      findMany: (a: { where: { OR: Parameters<typeof matchSwitch>[1] } }) =>
        Promise.resolve(s.switches.filter((x) => matchSwitch(x, a.where.OR))),
    },
    workspacePause: { findUnique: () => Promise.resolve(s.pause) },
    approvalAllowGrant: { findMany: () => Promise.resolve(s.blocks) },
    toolAction: { findMany: () => Promise.resolve(s.actions) },
  }) as never;
const state = (s: State, platform = false) =>
  hostPolicyState(db(s), 'h1', platform);
const ver = async (s: State, platform = false) =>
  (await state(s, platform)).version;

describe('hostPolicyState version', () => {
  it('is stable and opaque', async () => {
    const v = await ver(base());
    expect(v).toBe(await ver(base()));
    expect(v).toMatch(/^[0-9a-f]{16}$/);
    expect(HOST_RULES_VERSION).toMatch(/^[0-9a-f]{8}$/);
  });

  const flips: Array<[string, (s: State) => void]> = [
    [
      'a newer published policy version',
      (s) =>
        (s.policies = [{ id: 'v2', content: rule('*', 'shell', 'ALLOW') }]),
    ],
    [
      'a tenant kill switch',
      (s) => s.switches.push({ id: 'k1', scope: 'TENANT', targetId: null }),
    ],
    [
      'a kill switch on this host',
      (s) => s.switches.push({ id: 'k1', scope: 'AGENT', targetId: 'h1' }),
    ],
    [
      'a kill switch on a host tool',
      (s) => s.switches.push({ id: 'k1', scope: 'TOOL', targetId: 't-cursor' }),
    ],
    ['pause', (s) => (s.pause = { paused: true })],
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

  it('does not change for an unrelated agent, group or tool kill switch', async () => {
    const s = base();
    const before = await ver(s);
    s.switches.push(
      { id: 'k1', scope: 'AGENT', targetId: 'other-agent' },
      { id: 'k2', scope: 'AGENT_GROUP', targetId: 'g1' },
      { id: 'k3', scope: 'TOOL', targetId: 'some-other-tool' },
    );
    expect(await ver(s)).toBe(before);
  });

  it('changes when the platform kill switch turns on', async () => {
    expect(await ver(base(), true)).not.toBe(await ver(base(), false));
  });
});

describe('hostPolicyState restrictiveReadRule', () => {
  const restrictive = async (content: unknown) => {
    const s = base();
    s.policies = [{ id: 'v1', content }];
    return (await state(s)).restrictiveReadRule;
  };
  it('is false with no read rule', async () => {
    expect(await restrictive(rule('*', 'shell', 'DENY'))).toBe(false);
    expect(await restrictive(rule('host.cursor', 'read', 'ALLOW'))).toBe(false);
    expect(await restrictive(rule('some.other', 'read', 'DENY'))).toBe(false);
  });
  it('is true for a DENY read rule on a host tool', async () => {
    expect(await restrictive(rule('host.cursor', 'read', 'DENY'))).toBe(true);
  });
  it('is true for an APPROVAL_REQUIRED rule on every tool and action', async () => {
    expect(await restrictive(rule('*', '*', 'APPROVAL_REQUIRED'))).toBe(true);
  });
  it('is true when the content cannot be read', async () => {
    expect(await restrictive({ nope: 1 })).toBe(true);
  });
  it('ignores a DRAFT rule, which the query never returns', async () => {
    const s = base();
    s.policies = []; // only PUBLISHED versions are selected; the draft is not in the result
    expect((await state(s)).restrictiveReadRule).toBe(false);
  });
});

describe('config poll', () => {
  const ctrl = (getClient: () => Promise<unknown>) =>
    Object.assign(Object.create(HostConfigController.prototype), {
      tenants: { getClient },
      platformKill: { isActive: () => Promise.resolve(false) },
      logger: { warn: vi.fn(), error: vi.fn() },
    }) as unknown as {
      policyState(h: HostContext): Promise<{
        version: string;
        restrictiveReadRule: boolean;
      }>;
    };

  it('is the opaque token for an approved device', async () => {
    const r = await ctrl(() => Promise.resolve(db(base()))).policyState(host);
    expect(r.version).toMatch(/^[0-9a-f]{16}$/);
    expect(r.restrictiveReadRule).toBe(false);
  });
  it('is a fixed revoked sentinel for a PENDING device', async () => {
    const r = await ctrl(() => Promise.resolve(db(base()))).policyState({
      ...host,
      status: 'PENDING',
    });
    expect(r.version).toBe('revoked:PENDING');
  });
  it('fails the poll with 503 when the read fails', async () => {
    await expect(
      ctrl(() => Promise.reject(new Error('db'))).policyState(host),
    ).rejects.toBeInstanceOf(ServiceUnavailableException);
  });
});
