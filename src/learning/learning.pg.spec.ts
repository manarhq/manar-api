import { PrismaPg } from '@prisma/adapter-pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PrismaClient } from '../generated/tenant-client/client';

/**
 * Against a real, migrated tenant database. Skipped unless LEARNING_DB_URL is set:
 *   LEARNING_DB_URL=postgresql://... vitest run src/learning/learning.pg.spec.ts
 * The 7 days of learning mode are anchored on the first approval, enforced by a trigger so no
 * code path can move it.
 */
const url = process.env.LEARNING_DB_URL;
describe.skipIf(!url)('first approval anchor (postgres)', () => {
  let db: PrismaClient;
  const t0 = new Date('2026-11-01T10:00:00Z');
  const t1 = new Date('2026-11-04T10:00:00Z');
  const first = async (id: string) =>
    (await db.host.findUniqueOrThrow({ where: { id } })).firstApprovedAt;

  beforeAll(async () => {
    db = new PrismaClient({ adapter: new PrismaPg({ connectionString: url }) });
    await db.hostGroup.create({
      data: { id: 'lg', name: 'lg', updatedAt: new Date() },
    });
  });
  afterAll(async () => {
    await db.host.deleteMany();
    await db.hostGroup.deleteMany();
    await db.$disconnect();
  });
  const mk = (id: string, approvedAt: Date | null) =>
    db.host.create({
      data: {
        id,
        hostGroupId: 'lg',
        machineId: id,
        hostname: id,
        os: 'linux',
        keyType: 'SOFTWARE',
        registeredFromIp: '1.1.1.1',
        keyFingerprint: id,
        approvedAt,
        updatedAt: new Date(),
      } as never,
    });

  it('is set by the first approval, and null for a device never approved', async () => {
    await mk('p1', null);
    expect(await first('p1')).toBeNull();
    await mk('p2', t0);
    expect(await first('p2')).toEqual(t0);
  });

  it('a re-approval (rekey, revive, rule) does not move it', async () => {
    await db.host.update({ where: { id: 'p1' }, data: { approvedAt: t0 } });
    expect(await first('p1')).toEqual(t0);
    await db.host.update({ where: { id: 'p1' }, data: { approvedAt: null } });
    await db.host.update({ where: { id: 'p1' }, data: { approvedAt: t1 } });
    expect(await first('p1')).toEqual(t0);
    expect(
      (await db.host.findUniqueOrThrow({ where: { id: 'p1' } })).approvedAt,
    ).toEqual(t1);
  });

  it('cannot be reset or rewritten by an update', async () => {
    await db.host.update({
      where: { id: 'p2' },
      data: { firstApprovedAt: null },
    });
    expect(await first('p2')).toEqual(t0);
    await db.host.update({
      where: { id: 'p2' },
      data: { firstApprovedAt: t1 },
    });
    expect(await first('p2')).toEqual(t0);
  });
});
