import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { afterAll, describe, expect, it } from 'vitest';
import { ControlPrismaService } from './control-prisma.service';

/** Real Postgres: CONTROL_DATABASE_URL (migrations applied). Re-runs the sector backfill of 20261105130000_ai_default_on. */
const url = process.env.CONTROL_DATABASE_URL;
describe.skipIf(!url)('tenant sector backfill (postgres)', () => {
  const control = new ControlPrismaService({ get: () => url } as never);
  const ids: string[] = [];
  afterAll(async () => {
    await control.enterpriseProfile.deleteMany({
      where: { tenantId: { in: ids } },
    });
    await control.tenant.deleteMany({ where: { id: { in: ids } } });
    await control.$disconnect();
  });

  it('marks Government and commercial from what is known, personal as commercial, the rest unknown', async () => {
    await control.$connect();
    const mk = async (data: object = {}) => {
      const t = await control.tenant.create({
        data: {
          slug: `sec-${randomUUID().slice(0, 8)}`,
          name: 's',
          status: 'ACTIVE',
          ...data,
        },
      });
      ids.push(t.id);
      return t;
    };
    const profile = (tenantId: string, sector: 'GOVERNMENT' | 'ENTERPRISE') =>
      control.enterpriseProfile.create({
        data: { tenantId, sector, publicSlug: `sec-${randomUUID()}` },
      });
    const gov = await mk();
    await profile(gov.id, 'GOVERNMENT');
    const ent = await mk();
    await profile(ent.id, 'ENTERPRISE');
    const personal = await mk({ kind: 'PERSONAL' });
    const company = await mk({ kind: 'COMPANY' });

    const sql = readFileSync(
      'prisma/control/migrations/20261105130000_ai_default_on/migration.sql',
      'utf8',
    );
    const backfill = sql
      .slice(sql.indexOf('UPDATE "tenants" t SET "sector"'))
      .split(/;\s*\n/)
      .map((s) => s.trim())
      .filter((s) => s.startsWith('UPDATE'));
    for (const statement of backfill)
      await control.$executeRawUnsafe(statement);

    const sector = async (id: string) =>
      (await control.tenant.findUniqueOrThrow({ where: { id } })).sector;
    expect(await sector(gov.id)).toBe('GOVERNMENT');
    expect(await sector(ent.id)).toBe('COMMERCIAL');
    expect(await sector(personal.id)).toBe('COMMERCIAL');
    expect(await sector(company.id)).toBeNull();
  });
});
