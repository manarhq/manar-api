import { describe, expect, it } from 'vitest';
import {
  ALLOW_GRANT_TTL_MS,
  createAllowGrant,
  findLiveAllowGrant,
} from './allow-grants';

type Row = Record<string, unknown> & { expiresAt: Date };

/** One in-memory tenant database; `where` is applied the way Prisma would. */
function fakeTenantDb() {
  const rows: Row[] = [];
  const client = {
    approvalAllowGrant: {
      create: ({ data }: { data: Row }) => {
        const row = { id: `g${rows.length + 1}`, revokedAt: null, ...data };
        rows.push(row);
        return Promise.resolve(row);
      },
      findFirst: ({ where }: { where: Record<string, unknown> }) => {
        const hit = rows.find((r) =>
          Object.entries(where).every(([k, v]) =>
            k === 'expiresAt'
              ? r.expiresAt > (v as { gt: Date }).gt
              : r[k] === v,
          ),
        );
        return Promise.resolve(hit ?? null);
      },
    },
  };
  return client as never;
}

const T0 = new Date('2026-11-01T08:00:00Z');
const target = {
  toolId: 'host.cursor',
  actionId: 'file.read',
  resource: '/home/u/.aws/credentials',
};

describe('allow grants', () => {
  it('lives for exactly 8 hours', async () => {
    const db = fakeTenantDb();
    const g = await createAllowGrant(db, {
      scope: { hostId: 'h1' },
      target,
      createdBy: 'u',
      sourceId: 's',
      now: T0,
    });
    expect(g.expiresAt.getTime() - T0.getTime()).toBe(ALLOW_GRANT_TTL_MS);
    const just = new Date(T0.getTime() + ALLOW_GRANT_TTL_MS - 1);
    expect(
      await findLiveAllowGrant(db, { hostId: 'h1' }, target, just),
    ).not.toBeNull();
    const after = new Date(T0.getTime() + ALLOW_GRANT_TTL_MS);
    expect(
      await findLiveAllowGrant(db, { hostId: 'h1' }, target, after),
    ).toBeNull();
  });

  it('is scope-exact: other resource, action, tool and host are not covered', async () => {
    const db = fakeTenantDb();
    await createAllowGrant(db, {
      scope: { hostId: 'h1' },
      target,
      createdBy: 'u',
      sourceId: 's',
      now: T0,
    });
    const now = new Date(T0.getTime() + 1000);
    const find = (
      scope: { hostId: string } | { agentId: string },
      t = target,
    ) => findLiveAllowGrant(db, scope, t, now);
    expect(await find({ hostId: 'h1' })).not.toBeNull();
    expect(
      await find(
        { hostId: 'h1' },
        { ...target, resource: '/home/u/.aws/config' },
      ),
    ).toBeNull();
    expect(
      await find(
        { hostId: 'h1' },
        { ...target, resource: '/home/u/.aws/credentials2' },
      ),
    ).toBeNull();
    expect(
      await find({ hostId: 'h1' }, { ...target, actionId: 'file.write' }),
    ).toBeNull();
    expect(
      await find({ hostId: 'h1' }, { ...target, toolId: 'host.windsurf' }),
    ).toBeNull();
    expect(await find({ hostId: 'h2' })).toBeNull();
    expect(await find({ agentId: 'h1' })).toBeNull();
  });

  it('cannot cross tenants: each tenant has its own database', async () => {
    const a = fakeTenantDb();
    const b = fakeTenantDb();
    await createAllowGrant(a, {
      scope: { hostId: 'h1' },
      target,
      createdBy: 'u',
      sourceId: 's',
      now: T0,
    });
    expect(
      await findLiveAllowGrant(b, { hostId: 'h1' }, target, T0),
    ).toBeNull();
  });

  it('refuses a scope with neither or both ids', async () => {
    const db = fakeTenantDb();
    await expect(
      createAllowGrant(db, {
        scope: {} as never,
        target,
        createdBy: 'u',
        sourceId: 's',
      }),
    ).rejects.toThrow();
    expect(
      await findLiveAllowGrant(
        db,
        { hostId: 'h', agentId: 'a' } as never,
        target,
      ),
    ).toBeNull();
  });
});
