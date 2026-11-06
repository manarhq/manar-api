import { Client } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { readAuditEventsPaged } from './evidence-export.service';

/**
 * Real Postgres: an event whose sequence is lower than rows already read commits between two
 * pages (out-of-order commit). Pages at separate snapshots would return a view that mixes
 * "before" and "after"; one REPEATABLE READ transaction returns exactly the state at its start.
 */
const url = process.env.CONTROL_DATABASE_URL;
const table = `evidence_snap_${Math.random().toString(36).slice(2, 10)}`;

describe.skipIf(!url)('readAuditEventsPaged snapshot (postgres)', () => {
  let admin: Client;
  beforeAll(async () => {
    admin = new Client({ connectionString: url });
    await admin.connect();
    await admin.query(`CREATE TABLE ${table} (sequence int primary key)`);
  });
  afterAll(async () => {
    await admin.query(`DROP TABLE IF EXISTS ${table}`);
    await admin.end();
  });

  /** A tenant client over a dedicated connection, with a hook before each page after the first. */
  function client(beforeNextPage: () => Promise<void>) {
    return {
      async $transaction(
        fn: (tx: unknown) => Promise<unknown>,
        opts: { isolationLevel: string },
      ) {
        const c = new Client({ connectionString: url });
        await c.connect();
        try {
          expect(opts.isolationLevel).toBe('RepeatableRead');
          await c.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
          let pages = 0;
          const tx = {
            $executeRaw: () => Promise.resolve(0),
            auditEvent: {
              findMany: async (a: {
                where: { AND?: [unknown, { sequence: { gt: number } }] };
                take: number;
              }) => {
                if (pages++ > 0) await beforeNextPage();
                const gt = a.where.AND?.[1].sequence.gt ?? 0;
                const r = await c.query(
                  `SELECT sequence FROM ${table} WHERE sequence > $1 ORDER BY sequence LIMIT $2`,
                  [gt, a.take],
                );
                return r.rows as { sequence: number }[];
              },
            },
          };
          const out = await fn(tx);
          await c.query('COMMIT');
          return out;
        } finally {
          await c.end();
        }
      },
    };
  }

  it('an event committing out of sequence order mid-export does not make the result inconsistent', async () => {
    await admin.query(
      `INSERT INTO ${table} VALUES (1),(2),(4),(5),(6)`, // 3 is still uncommitted elsewhere
    );
    const got = await readAuditEventsPaged(
      client(async () => {
        await admin.query(`INSERT INTO ${table} VALUES (3)`); // commits after page 1 was read
      }) as never,
      {},
      2,
    );
    // The snapshot taken at the start: exactly what was committed then, every row once.
    expect(got.map((r) => r.sequence)).toEqual([1, 2, 4, 5, 6]);
    // A later export has it.
    const later = await readAuditEventsPaged(
      client(async () => {}) as never,
      {},
      2,
    );
    expect(later.map((r) => r.sequence)).toEqual([1, 2, 3, 4, 5, 6]);
  });
});
