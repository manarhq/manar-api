import { describe, expect, it, vi } from 'vitest';
import { readAuditEventsPaged } from './evidence-export.service';

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
    const client = { auditEvent: { findMany } };
    const got = await readAuditEventsPaged(
      client as never,
      { eventType: 'x' },
      3,
    );
    expect(got.map((r) => r.id)).toEqual(rows.map((r) => r.id));
    expect(findMany).toHaveBeenCalledTimes(3); // 3 + 3 + 1
    expect(findMany.mock.calls.every(([a]) => a.take === 3)).toBe(true);
  });

  it('a result that fits one page is one statement', async () => {
    const findMany = vi.fn().mockResolvedValue([{ id: 'a', sequence: 1 }]);
    await readAuditEventsPaged({ auditEvent: { findMany } } as never, {}, 5);
    expect(findMany).toHaveBeenCalledTimes(1);
  });
});
