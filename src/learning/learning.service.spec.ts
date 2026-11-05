import { ConflictException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { LearningService, UNSCOPED } from './learning.service';

const NOW = new Date('2026-11-05T12:00:00Z');
const day = (n: number) => new Date(NOW.getTime() - n * 86_400_000);

function world(
  over: {
    tenant?: { kind?: string; learningMode?: string | null } | null;
    sector?: string | null;
    host?: Record<string, unknown> | null;
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
            : { kind: 'COMPANY', learningMode: null, ...over.tenant },
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
                approvedAt: day(2),
                learningStartedAt: null,
                learningOff: false,
                status: 'APPROVED',
                removedAt: null,
                ...over.host,
              },
        ),
    },
    learningObservation: {
      upsert: ({
        where,
        create,
        update,
      }: {
        where: { hostId_toolId_actionId_scope: Record<string, string> };
        create: Record<string, unknown>;
        update: { count: { increment: number } };
      }) => {
        const k = where.hostId_toolId_actionId_scope;
        const hit = obs.find(
          (o) =>
            o.hostId === k.hostId &&
            o.toolId === k.toolId &&
            o.actionId === k.actionId &&
            o.scope === k.scope,
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
const serve = (w: ReturnType<typeof world>, req = edit, risk = 35) =>
  w.svc.serve(w.client, 't1', { hostId: 'h1' }, req, risk, NOW);

describe('who learns (decision 36)', () => {
  it.each([
    ['company, default', { tenant: { kind: 'COMPANY' } }, true, 'default'],
    ['personal, default', { tenant: { kind: 'PERSONAL' } }, true, 'default'],
    ['sample workspace', { tenant: { kind: 'SAMPLE' } }, false, 'default'],
    ['government, default', { sector: 'GOVERNMENT' }, false, 'default'],
    ['enterprise sector', { sector: 'ENTERPRISE' }, true, 'default'],
    [
      'admin turned off',
      { tenant: { learningMode: 'off' } },
      false,
      'workspace',
    ],
    [
      'government, admin turned on',
      { tenant: { learningMode: 'on' }, sector: 'GOVERNMENT' },
      true,
      'workspace',
    ],
    ['unknown workspace', { tenant: null }, false, 'default'],
  ])('%s', async (_n, over, enabled, source) => {
    const c = await world(over).svc.config('t1');
    expect(c).toMatchObject({ enabled, source });
  });
});

describe('serving an ask while a device learns', () => {
  it('serves, and counts what would have asked by folder', async () => {
    const w = world();
    expect(await serve(w)).toBe(true);
    expect(
      await serve(w, { ...edit, resource: '/home/sara/proj/src/b.ts' }),
    ).toBe(true);
    expect(w.obs).toHaveLength(1);
    expect(w.obs[0]).toMatchObject({
      scope: '/home/sara/proj/src/*',
      count: 2,
    });
  });
  it('commands are counted without a scope', async () => {
    const w = world();
    expect(
      await serve(
        w,
        { toolId: 'host.cursor', actionId: 'shell', resource: 'pnpm test' },
        30,
      ),
    ).toBe(true);
    expect(w.obs[0]).toMatchObject({ scope: UNSCOPED });
  });
  it('not after 7 days, not when off for the device, not when the workspace is off', async () => {
    expect(await serve(world({ host: { approvedAt: day(8) } }))).toBe(false);
    expect(await serve(world({ host: { learningOff: true } }))).toBe(false);
    expect(
      await serve(
        world({ host: { approvedAt: day(30), learningStartedAt: day(1) } }),
      ),
    ).toBe(true);
    expect(await serve(world({ tenant: { learningMode: 'off' } }))).toBe(false);
    expect(await serve(world({ host: null }))).toBe(false);
  });
  it('never high risk, secrets, climbs or risky commands', async () => {
    const w = world();
    expect(
      await serve(w, { ...edit, actionId: 'shell', resource: 'rm -rf x' }, 70),
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
        30,
      ),
    ).toBe(false);
    expect(w.obs).toHaveLength(0);
  });
});

describe('suggestions', () => {
  it('accepting makes a narrow, one-year, device-scoped grant with origin learning', async () => {
    const w = world();
    await serve(w);
    const r = await w.svc.accept(w.client, 't1', 'o0', { id: 'u1' });
    expect(r.grantId).toBe('g1');
    expect(w.grants[0]).toMatchObject({
      hostId: 'h1',
      origin: 'learning',
      resourcePattern: '/home/sara/proj/src/*',
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
      { toolId: 'host.cursor', actionId: 'shell', resource: 'pnpm test' },
      30,
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
