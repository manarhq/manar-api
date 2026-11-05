import { PrismaPg } from '@prisma/adapter-pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PrismaClient } from '../generated/tenant-client/client';
import { FrictionService } from './friction.service';

/**
 * Against a real, migrated tenant database. Skipped unless FRICTION_DB_URL is set:
 *   FRICTION_DB_URL=postgresql://... vitest run src/friction/friction.pg.spec.ts
 */
const url = process.env.FRICTION_DB_URL;
describe.skipIf(!url)('friction rollup on PostgreSQL', () => {
  let db: PrismaClient;
  const svc = new FrictionService({} as never, {} as never);
  const NOW = new Date('2026-11-05T12:00:00Z');
  const at = (h: number, m = 0, s = 0, d = 5) =>
    new Date(Date.UTC(2026, 10, d, h, m, s));
  let n = 0;
  const ap = (
    hostId: string,
    createdAt: Date,
    status: string,
    answerAfterSec: number | null,
    over: Record<string, unknown> = {},
  ) =>
    db.hostApproval.create({
      data: {
        id: `a${n++}`,
        hostId,
        toolId: 'host.cursor',
        actionId: 'edit',
        resource: '/home/u/p/a.ts',
        summary: 's',
        status: status as never,
        createdAt,
        expiresAt: new Date(createdAt.getTime() + 120_000),
        ...(answerAfterSec !== null
          ? {
              decidedAt: new Date(createdAt.getTime() + answerAfterSec * 1000),
              decidedBy: 'x',
            }
          : {}),
        ...over,
      },
    });

  beforeAll(async () => {
    db = new PrismaClient({ adapter: new PrismaPg({ connectionString: url }) });
    await db.hostGroup.create({
      data: { id: 'fg', name: 'fg', updatedAt: new Date() },
    });
    for (const [id, owner] of [
      ['fA', 'alice'],
      ['fB', 'bob'],
      ['fC', null],
    ] as const)
      await db.host.create({
        data: {
          id,
          hostGroupId: 'fg',
          machineId: id,
          hostname: id,
          os: 'linux',
          keyType: 'SOFTWARE',
          registeredFromIp: '1.1.1.1',
          keyFingerprint: id,
          status: 'APPROVED',
          ownerSubject: owner,
          updatedAt: new Date(),
        } as never,
      });
    // alice: approved in 10 s, approved in 20 s, denied in 5 s then approved 2 h later, timed out
    await ap('fA', at(9), 'APPROVED', 10);
    await ap('fA', at(9, 5), 'APPROVED', 20);
    await ap('fA', at(10), 'DENIED', 5);
    await ap('fA', at(12, 0, 0), 'APPROVED', 5);
    await ap('fA', at(11), 'EXPIRED', null);
    // bob: one deny that is never approved; yesterday one approval
    await ap('fB', at(8), 'DENIED', 3, { resource: '/other' });
    await ap('fB', at(8, 0, 0, 4), 'APPROVED', 30);
    // a deny followed by an approval more than 24 h later does not count
    await ap('fB', at(7, 0, 0, 1), 'DENIED', 2, { resource: '/late' });
    await ap('fB', at(9, 0, 0, 3), 'APPROVED', 2, { resource: '/late' });
    // unowned device
    await ap('fC', at(9, 30), 'APPROVED', 6);
  });
  afterAll(async () => {
    await db.frictionDaily.deleteMany();
    await db.hostApproval.deleteMany();
    await db.host.deleteMany();
    await db.hostGroup.deleteMany();
    await db.$disconnect();
  });

  it('rolls up prompts, answers, denies later approved, answer time and blocked time', async () => {
    const r = await svc.report(db, { subject: 'alice', admin: true }, 7, NOW);
    const today = r.series.at(-1)!;
    expect(today).toMatchObject({
      prompts: 7,
      approvals: 4,
      denies: 2,
      expired: 1,
      deniedLaterApproved: 1,
      answered: 6,
    });
    // blocked: 10+20+5+5 (alice) + 3 (bob) + 6 (unowned) answered seconds, plus 2 min timed out
    expect(today.blockedMinutes).toBe(2.8);
    expect(today.avgAnswerSeconds).toBe(8.2);
    expect(r.scope).toBe('workspace');
    expect(r.developers).toBe(2);
    expect(r.people!.map((p) => p.prompts)).toEqual([5, 4, 1]);
  });

  it('the 24-hour window is respected', async () => {
    const r = await svc.report(db, { subject: 'bob', admin: true }, 7, NOW);
    const d1 = r.series.find((s) => s.day === '2026-11-01')!;
    expect(d1).toMatchObject({ prompts: 1, denies: 1, deniedLaterApproved: 0 });
  });

  it('a person who is not an approver sees only their own devices', async () => {
    const r = await svc.report(db, { subject: 'alice', admin: false }, 7, NOW);
    expect(r.scope).toBe('me');
    expect(r.people).toBeUndefined();
    expect(r.totals.prompts).toBe(5);
  });

  it('is idempotent, and today is recomputed when a late answer lands', async () => {
    const before = await svc.report(
      db,
      { subject: 'alice', admin: true },
      7,
      NOW,
    );
    await svc.refresh(db, 7, NOW);
    expect(
      await db.frictionDaily.count({ where: { day: new Date('2026-11-05') } }),
    ).toBe(3);
    await ap('fA', at(11, 30), 'APPROVED', 4);
    const after = await svc.report(
      db,
      { subject: 'alice', admin: true },
      7,
      NOW,
    );
    expect(after.totals.prompts).toBe(before.totals.prompts + 1);
  });
});
