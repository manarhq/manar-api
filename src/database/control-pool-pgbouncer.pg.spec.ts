import { PrismaPg } from '@prisma/adapter-pg';
import { describe, expect, it } from 'vitest';
import { pgPoolOptions, poolSettings } from './pool-options';

/**
 * Runs only when PGBOUNCER_URL points at a PgBouncer with the default (empty)
 * ignore_startup_parameters, as Azure's is. The lab starts one in front of the CI Postgres.
 */
const url = process.env.PGBOUNCER_URL;
const settings = (kind: 'control' | 'tenant') =>
  poolSettings(() => undefined, kind);

async function select1(kind: 'control' | 'tenant') {
  const adapter = new PrismaPg(pgPoolOptions(url!, settings(kind)));
  const conn = await adapter.connect();
  try {
    return await conn.queryRaw({
      sql: 'SELECT 1 AS one',
      args: [],
      argTypes: [],
    });
  } finally {
    await conn.dispose();
  }
}

describe.skipIf(!url)('control pool behind PgBouncer', () => {
  it('connects and queries: the control pool sends no startup parameters', async () => {
    const r = await select1('control');
    expect(r.rows).toEqual([[1]]);
  });

  it('documents why: a statement_timeout startup parameter is rejected by this PgBouncer', async () => {
    await expect(select1('tenant')).rejects.toThrow(/startup parameter/i);
  });
});
