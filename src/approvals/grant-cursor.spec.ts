import { describe, expect, it, vi } from 'vitest';
import { ApprovalsController } from './approvals.controller';
import { decodeGrantCursor, encodeGrantCursor } from './grant-cursor';

describe('allow-grants cursor', () => {
  it('round-trips and refuses garbage', () => {
    const at = { createdAt: new Date('2026-11-05T10:00:00.000Z'), id: 'g9' };
    expect(decodeGrantCursor(encodeGrantCursor(at))).toEqual(at);
    for (const bad of [
      undefined,
      '',
      'x',
      Buffer.from('nope').toString('base64url'),
    ])
      expect(decodeGrantCursor(bad)).toBeNull();
  });
});

describe('GET /approvals/allow-grants is paginated', () => {
  const row = (i: number) => ({
    id: `g${i}`,
    origin: 'offer',
    hostId: 'h',
    host: { hostname: 'pc' },
    agentId: null,
    toolId: 'host.cursor',
    actionId: 'edit',
    resourcePattern: '/home/sara/proj/*',
    resource: '/home/sara/proj/a.ts',
    createdAt: new Date(Date.UTC(2026, 10, 5, 10, 0, 60 - i)),
    expiresAt: new Date('2027-11-05T10:00:00Z'),
    useCount: 0,
    lastUsedAt: null,
  });
  function controller(total: number) {
    const all = Array.from({ length: total }, (_, i) => row(i));
    const findMany = vi.fn((args: { take: number }) =>
      Promise.resolve(all.slice(0, args.take)),
    );
    const c = Object.create(
      ApprovalsController.prototype,
    ) as ApprovalsController;
    (c as unknown as { tenantDatabaseManager: unknown }).tenantDatabaseManager =
      {
        getClient: () => Promise.resolve({ approvalAllowGrant: { findMany } }),
      };
    return { c, findMany };
  }
  const auth = { tenant: { id: 't1' } } as never;

  it('returns one page, newest first, with a cursor for the next', async () => {
    const { c, findMany } = controller(120);
    const page = await c.listGrants(auth, '50');
    expect(page.items).toHaveLength(50);
    expect(page.nextCursor).toBeTruthy();
    const args = findMany.mock.calls[0]![0] as unknown as {
      take: number;
      orderBy: unknown;
    };
    expect(args.take).toBe(51);
    expect(args.orderBy).toEqual([{ createdAt: 'desc' }, { id: 'desc' }]);
  });
  it('the last page has no cursor; the limit is clamped to 1..200 with a default of 50', async () => {
    expect(
      (await controller(3).c.listGrants(auth, '50')).nextCursor,
    ).toBeNull();
    const big = controller(500);
    expect((await big.c.listGrants(auth, '9999')).items).toHaveLength(200);
    expect((await big.c.listGrants(auth, undefined)).items).toHaveLength(50);
    expect((await big.c.listGrants(auth, '0')).items).toHaveLength(50);
  });
  it('a cursor continues after the last row it names', async () => {
    const { c, findMany } = controller(10);
    const first = await c.listGrants(auth, '5');
    await c.listGrants(auth, '5', first.nextCursor!);
    const where = (
      findMany.mock.calls[1]![0] as unknown as { where: { OR: unknown[] } }
    ).where;
    expect(where.OR).toHaveLength(2);
  });
});
