import { ConflictException, ForbiddenException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { computeContentHash } from '../policy/policy-content-codec';
import {
  START_MODE_POLICY_NAME,
  START_MODE_PRESETS,
} from '../workspace/start-mode.presets';
import { LearningService, UNSCOPED } from './learning.service';

const NOW = new Date('2026-11-05T12:00:00Z');
const day = (n: number) => new Date(NOW.getTime() - n * 86_400_000);
const hash = (m: 'ask' | 'strict' | 'watch') =>
  computeContentHash(START_MODE_PRESETS[m]);

function world(
  over: {
    tenant?: {
      kind?: string;
      learningMode?: string | null;
      sector?: string | null;
    } | null;
    sector?: string | null;
    host?: Record<string, unknown> | null;
    /** What the policy version that asked is. */
    version?: { name: string; contentHash: string } | null;
    /** By policy version id, for a request several policies ask about. */
    versions?: Record<string, { name: string; contentHash: string }>;
    sites?: boolean;
  } = {},
) {
  const obs: Array<Record<string, unknown>> = [];
  const grants: Array<Record<string, unknown>> = [];
  const control = {
    tenant: {
      findUnique: () =>
        Promise.resolve(
          over.tenant === null
            ? null
            : {
                kind: 'COMPANY',
                learningMode: null,
                sector: 'COMMERCIAL',
                ...over.tenant,
              },
        ),
      update: vi.fn(() => Promise.resolve({})),
    },
    enterpriseProfile: {
      findUnique: () =>
        Promise.resolve(over.sector ? { sector: over.sector } : null),
    },
  };
  const audit = { recordSafely: vi.fn().mockResolvedValue(undefined) };
  const client: Record<string, unknown> = {
    host: {
      findUnique: () =>
        Promise.resolve(
          over.host === null
            ? null
            : {
                firstApprovedAt: day(2),
                learningStartedAt: null,
                learningOff: false,
                status: 'APPROVED',
                removedAt: null,
                ...over.host,
              },
        ),
    },
    policyVersion: {
      findUnique: ({ where }: { where: { id: string } }) => {
        const v = over.versions?.[where.id] ?? over.version;
        return Promise.resolve(
          v ? { contentHash: v.contentHash, policy: { name: v.name } } : null,
        );
      },
    },
    hostApproval: {
      findFirst: () => Promise.resolve(over.sites ? { id: 'a' } : null),
    },
    learningObservation: {
      upsert: ({
        where,
        create,
        update,
      }: {
        where: { hostId_toolId_actionId_scope_askKey: Record<string, string> };
        create: Record<string, unknown>;
        update: { count: { increment: number } };
      }) => {
        const k = where.hostId_toolId_actionId_scope_askKey;
        const hit = obs.find(
          (o) =>
            o.hostId === k.hostId &&
            o.toolId === k.toolId &&
            o.actionId === k.actionId &&
            o.scope === k.scope &&
            o.askKey === k.askKey,
        );
        if (hit) (hit.count as number) += update.count.increment;
        else
          obs.push({ id: `o${obs.length}`, count: 1, state: 'NEW', ...create });
        return Promise.resolve({});
      },
      findUnique: ({ where }: { where: { id: string } }) =>
        Promise.resolve(obs.find((o) => o.id === where.id) ?? null),
      updateMany: ({
        where,
        data,
      }: {
        where: { id: string; state: string };
        data: Record<string, unknown>;
      }) => {
        const o = obs.find((x) => x.id === where.id && x.state === where.state);
        if (!o) return Promise.resolve({ count: 0 });
        Object.assign(o, data);
        return Promise.resolve({ count: 1 });
      },
    },
    approvalAllowGrant: {
      create: ({ data }: { data: Record<string, unknown> }) => {
        grants.push(data);
        return Promise.resolve({ id: 'g1', ...data });
      },
    },
  };
  client.$transaction = (fn: (tx: unknown) => unknown) =>
    Promise.resolve(fn(client));
  const svc = new LearningService(control as never, audit as never);
  return { svc, client: client as never, obs, grants, control, audit };
}

const edit = {
  toolId: 'host.cursor',
  actionId: 'edit',
  resource: '/home/sara/proj/src/a.ts',
};
const ceiling = { riskScore: 35, askKey: 'ceiling' };
const serve = (
  w: ReturnType<typeof world>,
  req = edit,
  ask: {
    riskScore: number;
    askKey: string;
    policyVersionIds?: string[];
  } = ceiling,
) =>
  w.svc.serve(
    w.client,
    't1',
    { hostId: 'h1' },
    { resolvedPath: req.resource, ...req },
    ask,
    NOW,
  );

describe('who learns (decision 36)', () => {
  it.each([
    ['company, default', { tenant: { kind: 'COMPANY' } }, true, 'default'],
    ['personal, default', { tenant: { kind: 'PERSONAL' } }, true, 'default'],
    ['sample workspace', { tenant: { kind: 'SAMPLE' } }, false, 'default'],
    ['government, default', { sector: 'GOVERNMENT' }, false, 'default'],
    ['enterprise sector', { sector: 'ENTERPRISE' }, true, 'default'],
    // The workspace's own sector (staff-set) is the authority.
    [
      'workspace sector GOVERNMENT, no profile',
      { tenant: { sector: 'GOVERNMENT' } },
      false,
      'default',
    ],
    [
      'workspace sector GOVERNMENT with a stored "on"',
      { tenant: { sector: 'GOVERNMENT', learningMode: 'on' } },
      false,
      'default',
    ],
    [
      'workspace sector COMMERCIAL',
      { tenant: { sector: 'COMMERCIAL' } },
      true,
      'default',
    ],
    // Unknown could be Government: off until staff set it, whatever is stored.
    ['sector not recorded yet', { tenant: { sector: null } }, false, 'default'],
    [
      'sector not recorded, stored "on"',
      { tenant: { sector: null, learningMode: 'on' } },
      false,
      'default',
    ],
    [
      'no workspace sector but an Enterprise profile',
      { tenant: { sector: null }, sector: 'ENTERPRISE' },
      true,
      'default',
    ],
    [
      'admin turned off',
      { tenant: { learningMode: 'off' } },
      false,
      'workspace',
    ],
    ['unknown workspace', { tenant: null }, false, 'default'],
    // Government cannot be switched on, even if a value were stored
    [
      'government with a stored "on"',
      { tenant: { learningMode: 'on' }, sector: 'GOVERNMENT' },
      false,
      'default',
    ],
  ])('%s', async (_n, over, enabled, source) => {
    const c = await world(over).svc.config('t1');
    expect(c).toMatchObject({ enabled, source });
  });

  it('a workspace with no sector recorded cannot turn learning on: learning_needs_sector', async () => {
    const w = world({ tenant: { sector: null } });
    const err = await w.svc
      .setWorkspace('t1', 'on', { id: 'u' }, w.client)
      .catch((e: ForbiddenException) => e);
    expect(err).toBeInstanceOf(ForbiddenException);
    expect((err as ForbiddenException).getResponse()).toMatchObject({
      reason: 'learning_needs_sector',
    });
    expect(w.control.tenant.update).not.toHaveBeenCalled();
    expect((await w.svc.config('t1')).needsSector).toBe(true);
    // off is always fine
    await w.svc.setWorkspace('t1', 'off', { id: 'u' }, w.client);
    expect(w.control.tenant.update).toHaveBeenCalledTimes(1);
  });

  it('a workspace whose own sector is GOVERNMENT cannot turn learning on either', async () => {
    const w = world({ tenant: { sector: 'GOVERNMENT' } });
    await expect(
      w.svc.setWorkspace('t1', 'on', { id: 'u' }, w.client),
    ).rejects.toThrow(ForbiddenException);
    expect(w.control.tenant.update).not.toHaveBeenCalled();
  });

  it('a Government workspace cannot turn learning on: 403 with a clear message', async () => {
    const w = world({ sector: 'GOVERNMENT' });
    await expect(
      w.svc.setWorkspace('t1', 'on', { id: 'u' }, w.client),
    ).rejects.toThrow(ForbiddenException);
    await expect(
      w.svc.setWorkspace('t1', 'on', { id: 'u' }, w.client),
    ).rejects.toThrow(/not available in a Government workspace/);
    expect(w.control.tenant.update).not.toHaveBeenCalled();
    const err = await w.svc
      .setWorkspace('t1', 'on', { id: 'u' }, w.client)
      .catch((e: ForbiddenException) => e);
    expect((err as ForbiddenException).getResponse()).toMatchObject({
      reason: 'learning_not_available_government',
    });
    // off and default are fine
    await w.svc.setWorkspace('t1', 'off', { id: 'u' }, w.client);
    await w.svc.setWorkspace('t1', 'default', { id: 'u' }, w.client);
    expect(w.control.tenant.update).toHaveBeenCalledTimes(2);
  });
});

describe('which asks learning may quiet', () => {
  it('the risk ceiling', async () => {
    expect(await serve(world())).toBe(true);
  });
  it('the ask preset own rules, not strict, not watch, not an admin rule, not an unknown version', async () => {
    const ask = { riskScore: 35, askKey: 'p:abc', policyVersionIds: ['v1'] };
    const v = (name: string, contentHash: string) =>
      world({ version: { name, contentHash } });
    expect(await serve(v(START_MODE_POLICY_NAME, hash('ask')), edit, ask)).toBe(
      true,
    );
    expect(
      await serve(v(START_MODE_POLICY_NAME, hash('strict')), edit, ask),
    ).toBe(false);
    expect(
      await serve(v(START_MODE_POLICY_NAME, hash('watch')), edit, ask),
    ).toBe(false);
    expect(
      await serve(v(START_MODE_POLICY_NAME, 'edited-by-hand'), edit, ask),
    ).toBe(false);
    expect(await serve(v('my-rules', hash('ask')), edit, ask)).toBe(false);
    expect(await serve(world({ version: null }), edit, ask)).toBe(false);
    // Several policies ask: every one of them must be the "ask" preset.
    const presetAsk = {
      name: START_MODE_POLICY_NAME,
      contentHash: hash('ask'),
    };
    const admin = { name: 'my-rules', contentHash: 'x' };
    const both = { ...ask, policyVersionIds: ['v-ask', 'v-custom'] };
    expect(
      await serve(
        world({ versions: { 'v-ask': presetAsk, 'v-custom': admin } }),
        edit,
        both,
      ),
    ).toBe(false);
    expect(
      await serve(
        world({ versions: { 'v-ask': presetAsk, 'v-custom': admin } }),
        edit,
        { ...both, policyVersionIds: ['v-custom', 'v-ask'] },
      ),
    ).toBe(false);
    expect(
      await serve(
        world({
          versions: {
            'v-ask': presetAsk,
            'v-strict': { ...presetAsk, contentHash: hash('strict') },
          },
        }),
        edit,
        { ...both, policyVersionIds: ['v-ask', 'v-strict'] },
      ),
    ).toBe(false);
    expect(
      await serve(world({ versions: { 'v-ask': presetAsk } }), edit, {
        ...both,
        policyVersionIds: ['v-ask', 'v-ask'],
      }),
    ).toBe(true);
    expect(
      await serve(world(), edit, { ...ask, policyVersionIds: undefined }),
    ).toBe(false);
  });
});

describe('serving an ask while a device learns', () => {
  it('serves, and counts what would have asked by folder and ask', async () => {
    const w = world();
    expect(await serve(w)).toBe(true);
    expect(
      await serve(w, { ...edit, resource: '/home/sara/proj/src/b.ts' }),
    ).toBe(true);
    expect(w.obs).toHaveLength(1);
    expect(w.obs[0]).toMatchObject({
      scope: '/home/sara/proj/src/*',
      askKey: 'ceiling',
      count: 2,
    });
  });
  it('a read-only command is counted without a scope; a test run is not served', async () => {
    const w = world();
    const sh = { toolId: 'host.cursor', actionId: 'shell' };
    expect(
      await serve(
        w,
        { ...sh, resource: 'ls -la src' },
        { ...ceiling, riskScore: 30 },
      ),
    ).toBe(true);
    expect(w.obs[0]).toMatchObject({ scope: UNSCOPED });
    expect(
      await serve(
        w,
        { ...sh, resource: 'pnpm test' },
        { ...ceiling, riskScore: 30 },
      ),
    ).toBe(false);
    expect(
      await serve(
        w,
        { ...sh, resource: 'pnpm test' },
        { ...ceiling, riskScore: 70 },
      ),
    ).toBe(false);
  });
  it('file actions need a home project folder scope; dot folders at any depth ask', async () => {
    const w = world();
    for (const resource of [
      '/etc/hosts',
      '/home/sara/notes.txt',
      '/home/sara/proj/.git/hooks/pre-commit',
      '/home/sara/proj/.vscode/tasks.json',
      '/home/sara/proj/src/.cache/a.ts',
      'src/a.ts',
    ])
      expect(await serve(w, { ...edit, resource }), resource).toBe(false);
    expect(w.obs).toHaveLength(0);
  });
  it('a web fetch is served only for a site a person already approved here', async () => {
    const fetchReq = {
      toolId: 'host.cursor',
      actionId: 'webfetch',
      resource: 'https://docs.x.io/a',
    };
    const ask = { riskScore: 20, askKey: 'ceiling' };
    expect(await serve(world({ sites: false }), fetchReq, ask)).toBe(false);
    const seen = world({ sites: true });
    expect(await serve(seen, fetchReq, ask)).toBe(true);
    expect(seen.obs[0]).toMatchObject({ scope: 'https://docs.x.io/*' });
  });
  it('needs the device to vouch for a file path: absent, different or outside the home project asks', async () => {
    const w = world();
    expect(await serve(w)).toBe(true);
    for (const resolvedPath of [
      undefined,
      '/home/sara/.ssh/authorized_keys',
      '/etc/hosts',
    ])
      expect(await serve(w, { ...edit, resolvedPath } as never)).toBe(false);
  });
  it('not after 7 days from the FIRST approval, not when off for the device or the workspace', async () => {
    expect(await serve(world({ host: { firstApprovedAt: day(8) } }))).toBe(
      false,
    );
    expect(await serve(world({ host: { firstApprovedAt: null } }))).toBe(false);
    expect(await serve(world({ host: { learningOff: true } }))).toBe(false);
    expect(
      await serve(
        world({
          host: { firstApprovedAt: day(30), learningStartedAt: day(1) },
        }),
      ),
    ).toBe(true);
    expect(await serve(world({ tenant: { learningMode: 'off' } }))).toBe(false);
    expect(await serve(world({ host: null }))).toBe(false);
  });
  it('never high risk, secrets, climbs or risky commands', async () => {
    const w = world();
    expect(
      await serve(
        w,
        { ...edit, actionId: 'shell', resource: 'rm -rf x' },
        { ...ceiling, riskScore: 70 },
      ),
    ).toBe(false);
    expect(await serve(w, { ...edit, resource: '/home/sara/proj/.env' })).toBe(
      false,
    );
    expect(await serve(w, { ...edit, resource: '../../etc/passwd' })).toBe(
      false,
    );
    expect(
      await serve(
        w,
        { ...edit, actionId: 'shell', resource: 'git push --force' },
        { ...ceiling, riskScore: 30 },
      ),
    ).toBe(false);
    expect(w.obs).toHaveLength(0);
  });
});

describe('suggestions', () => {
  it('accepting makes a narrow, one-year grant bound to the ask it was seen under', async () => {
    const w = world();
    await serve(w);
    const r = await w.svc.accept(w.client, 't1', 'o0', { id: 'u1' });
    expect(r.grantId).toBe('g1');
    expect(w.grants[0]).toMatchObject({
      hostId: 'h1',
      origin: 'learning',
      resourcePattern: '/home/sara/proj/src/*',
      askKey: 'ceiling',
    });
    expect(w.obs[0]).toMatchObject({ state: 'ACCEPTED' });
    await expect(
      w.svc.accept(w.client, 't1', 'o0', { id: 'u1' }),
    ).rejects.toThrow(ConflictException);
  });
  it('cannot accept what has no scope, or a removed device', async () => {
    const w = world();
    await serve(
      w,
      { toolId: 'host.cursor', actionId: 'shell', resource: 'ls src' },
      { ...ceiling, riskScore: 30 },
    );
    await expect(
      w.svc.accept(w.client, 't1', 'o0', { id: 'u1' }),
    ).rejects.toThrow(ConflictException);
    const gone = world({ host: { removedAt: day(1) } });
    await serve(gone);
    await expect(
      gone.svc.accept(gone.client, 't1', 'o0', { id: 'u1' }),
    ).rejects.toThrow(ConflictException);
  });
  it('dismiss hides it once', async () => {
    const w = world();
    await serve(w);
    await w.svc.dismiss(w.client, 't1', 'o0', { id: 'u1' });
    expect(w.obs[0]).toMatchObject({ state: 'DISMISSED' });
    await expect(
      w.svc.dismiss(w.client, 't1', 'o0', { id: 'u1' }),
    ).rejects.toThrow(ConflictException);
  });
});
