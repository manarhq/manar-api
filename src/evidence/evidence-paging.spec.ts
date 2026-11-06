import { describe, expect, it, vi } from 'vitest';
import { readAuditEventsPaged } from './evidence-export.service';

/** A tenant client whose $transaction hands the callback a tx with the given findMany. */
function fakeClient(findMany: (args: never) => Promise<unknown>) {
  const txOptions: unknown[] = [];
  const tx = {
    $executeRaw: vi.fn().mockResolvedValue(0),
    auditEvent: { findMany },
  };
  return {
    txOptions,
    tx,
    client: {
      auditEvent: {
        findMany: () => {
          throw new Error('pages must be read inside the transaction');
        },
      },
      $transaction: (fn: (t: typeof tx) => unknown, opts: unknown) => {
        txOptions.push(opts);
        return fn(tx);
      },
    },
  };
}

describe('readAuditEventsPaged', () => {
  it('reads in bounded pages by sequence and returns every row once, in order', async () => {
    const rows = Array.from({ length: 7 }, (_, i) => ({
      id: `e${i}`,
      sequence: i + 1,
    }));
    const findMany = vi.fn(
      ({
        where,
        take,
      }: {
        where: { AND?: [unknown, { sequence: { gt: number } }] };
        take: number;
      }) => {
        const gt = where.AND?.[1].sequence.gt ?? 0;
        return Promise.resolve(
          rows.filter((r) => r.sequence > gt).slice(0, take),
        );
      },
    );
    const { client, txOptions, tx } = fakeClient(findMany);
    const got = await readAuditEventsPaged(
      client as never,
      { eventType: 'x' },
      3,
    );
    expect(got.map((r) => r.id)).toEqual(rows.map((r) => r.id));
    expect(findMany).toHaveBeenCalledTimes(3); // 3 + 3 + 1
    expect(findMany.mock.calls.every(([a]) => a.take === 3)).toBe(true);
    // One read-only REPEATABLE READ transaction for every page.
    expect(txOptions).toHaveLength(1);
    expect(txOptions[0]).toMatchObject({ isolationLevel: 'RepeatableRead' });
    expect(tx.$executeRaw).toHaveBeenCalledTimes(1);
  });

  it('a result that fits one page is one statement', async () => {
    const findMany = vi.fn().mockResolvedValue([{ id: 'a', sequence: 1 }]);
    const { client } = fakeClient(findMany);
    await readAuditEventsPaged(client as never, {}, 5);
    expect(findMany).toHaveBeenCalledTimes(1);
  });
});
