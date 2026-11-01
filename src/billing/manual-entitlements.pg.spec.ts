import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { ControlPrismaService } from '../database/control-prisma.service';

/** Real Postgres: set GROWTH_TEST_DATABASE_URL (control DB, all migrations applied). */
const url = process.env.GROWTH_TEST_DATABASE_URL;
describe.skipIf(!url)('manual entitlement backfill (postgres)', () => {
  const control = new ControlPrismaService({ get: () => url } as never);
  afterAll(async () => {
    await control.tenantEntitlement.deleteMany({
      where: { tenant: { slug: { startsWith: 'bf-' } } },
    });
    await control.tenant.deleteMany({ where: { slug: { startsWith: 'bf-' } } });
    await control.$disconnect();
  });

  it('gives existing company tenants a manual company plan, once, and leaves the rest', async () => {
    await control.$connect();
    const mk = (slug: string, kind: 'COMPANY' | 'PERSONAL') =>
      control.tenant.create({
        data: { slug, name: slug, kind, status: 'ACTIVE' },
      });
    const pilot = await mk('bf-pilot', 'COMPANY');
    const personal = await mk('bf-personal', 'PERSONAL');
    const paid = await mk('bf-paid', 'COMPANY');
    await control.tenantEntitlement.create({
      data: { tenantId: paid.id, plan: 'pro' },
    });

    const sql = readFileSync(
      join(
        __dirname,
        '../../prisma/control/migrations/20261101140000_manual_company_entitlements/migration.sql',
      ),
      'utf8',
    );
    const insert = sql.slice(sql.indexOf('INSERT INTO'));
    for (let i = 0; i < 2; i++) await control.$executeRawUnsafe(insert); // idempotent

    const row = (id: string) =>
      control.tenantEntitlement.findUnique({ where: { tenantId: id } });
    expect(await row(pilot.id)).toMatchObject({
      plan: 'company',
      status: 'active',
      manual: true,
      stripeCustomerId: null,
      stripeSubscriptionId: null,
    });
    expect(await row(personal.id)).toBeNull();
    expect(await row(paid.id)).toMatchObject({ plan: 'pro', manual: false });
  });
});
