import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * The backfill is SQL; its behaviour is proven against a real database in
 * `manual-entitlements.pg.spec.ts` (set GROWTH_TEST_DATABASE_URL). This guards the parts that must
 * not change by accident.
 */
describe('manual entitlement backfill migration', () => {
  const sql = readFileSync(
    join(
      __dirname,
      '../../prisma/control/migrations/20261101140000_manual_company_entitlements/migration.sql',
    ),
    'utf8',
  );
  it('only touches existing company tenants that have no row, and carries no Stripe ids', () => {
    expect(sql).toMatch(/t\."kind" = 'COMPANY'/);
    expect(sql).toMatch(/NOT EXISTS/);
    expect(sql.slice(sql.indexOf('INSERT INTO'))).not.toMatch(/stripe/i);
  });
});
