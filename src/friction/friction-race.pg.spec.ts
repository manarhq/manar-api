import { PrismaPg } from '@prisma/adapter-pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PrismaClient } from '../generated/tenant-client/client';
import { FrictionService } from './friction.service';

/**
 * Concurrent console reads must not fail (review, 6 Nov 2026: 4 of 8 got a unique-key 500 when two
 * refreshes inserted the same day). Needs its own migrated tenant database, because it seeds
 * hosts that would change the totals of friction.pg.spec.ts:
 *   FRICTION_RACE_DB_URL=postgresql://... vitest run src/friction/friction-race.pg.spec.ts
 */
const url = process.env.FRICTION_RACE_DB_URL;
describe.skipIf(!url)('friction refresh under concurrency (postgres)', () => {
  let db: PrismaClient;
  beforeAll(async () => {
    db = new PrismaClient({ adapter: new PrismaPg({ connectionString: url }) });
    await db.hostGroup.create({
      data: { id: 'rg', name: 'rg', updatedAt: new Date() },
    });
    await db.host.create({
      data: {
        id: 'rh',
        hostGroupId: 'rg',
        machineId: 'rh',
        hostname: 'rh',
        os: 'linux',
        keyType: 'SOFTWARE',
        registeredFromIp: '1.1.1.1',
        keyFingerprint: 'rh',
        status: 'APPROVED',
        ownerSubject: 'alice',
        updatedAt: new Date(),
      } as never,
    });
    const now = Date.now();
    for (let i = 0; i < 20; i++)
      await db.hostApproval.create({
        data: {
          id: `r${i}`,
          hostId: 'rh',
          toolId: 'host.cursor',
          actionId: 'edit',
          resource: '/home/u/p/a.ts',
          summary: 's',
          status: 'APPROVED' as never,
          createdAt: new Date(now - i * 3_600_000),
          expiresAt: new Date(now + 120_000),
          decidedAt: new Date(now - i * 3_600_000 + 5000),
          decidedBy: 'x',
        },
      });
  });
  afterAll(async () => {
    // The database is reused between runs: leave it empty.
    await db?.frictionDaily.deleteMany();
    await db?.hostApproval.deleteMany();
    await db?.host.deleteMany();
    await db?.hostGroup.deleteMany();
    await db?.$disconnect();
  });

  it('8 concurrent reports all succeed and agree', async () => {
    const svc = new FrictionService({} as never, {} as never);
    const res = await Promise.allSettled(
      Array.from({ length: 8 }, () =>
        svc.report(db, { subject: 'alice', admin: false }, 14),
      ),
    );
    const failed = res.filter((r) => r.status === 'rejected');
    expect(failed.map((f) => String(f.reason))).toEqual([]);
    const totals = res.map(
      (r) =>
        (r as PromiseFulfilledResult<{ totals: { prompts: number } }>).value
          .totals.prompts,
    );
    expect(new Set(totals)).toEqual(new Set([20]));
  });

  it('a second read right after does not rewrite the rollup', async () => {
    const svc = new FrictionService({} as never, {} as never); // one process
    await new Promise((r) => setTimeout(r, 20));
    const stamp = async () =>
      (await db.frictionDaily.aggregate({ _max: { updatedAt: true } }))._max
        .updatedAt;
    await svc.report(db, { subject: 'alice', admin: false }, 14);
    const first = await stamp();
    await svc.report(db, { subject: 'alice', admin: false }, 14);
    expect(await stamp()).toEqual(first);
  });
});
