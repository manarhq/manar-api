import { describe, expect, it } from 'vitest';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import type { KillSwitchService } from '../kill-switches/kill-switch.service';
import { TasksService, type TaskRecord } from './tasks.service';

/** A delegated task draws on its ancestors' execution budget instead of getting its own copy. */

function task(
  id: string,
  parentTaskId: string | null,
  maxExecutions: number | null,
  executionCount: number,
): TaskRecord {
  return {
    id,
    name: id,
    description: null,
    parentTaskId,
    requesterId: 'u',
    assignedAgentId: `agent-${id}`,
    status: 'ACTIVE',
    startsAt: new Date('2026-01-01T00:00:00Z'),
    expiresAt: new Date('2099-01-01T00:00:00Z'),
    maxExecutions,
    executionCount,
    allowedToolActions: [],
    allowedResourceSelectors: [],
    forbiddenActions: [],
    riskCeiling: 20,
    createdAt: new Date('2026-01-01T00:00:00Z'),
  };
}

/** An in-memory `task` table with Prisma's conditional-update semantics. */
function table(rows: TaskRecord[]) {
  const byId = new Map(rows.map((r) => [r.id, { ...r }]));
  const client = {
    task: {
      findUnique: ({ where }: { where: { id: string } }) =>
        Promise.resolve(byId.get(where.id) ?? null),
      update: ({
        where,
        data,
      }: {
        where: { id: string };
        data: { executionCount: { increment?: number; decrement?: number } };
      }) => {
        const row = byId.get(where.id)!;
        row.executionCount +=
          (data.executionCount.increment ?? 0) -
          (data.executionCount.decrement ?? 0);
        return Promise.resolve(row);
      },
      updateMany: ({
        where,
      }: {
        where: { id: string; executionCount: { lt: number } };
      }) => {
        const row = byId.get(where.id)!;
        if (row.executionCount >= where.executionCount.lt) {
          return Promise.resolve({ count: 0 });
        }
        row.executionCount += 1;
        return Promise.resolve({ count: 1 });
      },
    },
  } as unknown as TenantPrismaClient;
  return { client, count: (id: string) => byId.get(id)!.executionCount };
}

const service = new TasksService(
  {} as never,
  {} as never,
  {
    checkAgent: () => Promise.resolve({ killed: false }),
  } as unknown as KillSwitchService,
);

describe('TasksService.incrementExecutionCount shares budgets along the chain', () => {
  it('counts one execution on the task and every ancestor', async () => {
    const { client, count } = table([
      task('root', null, 10, 0),
      task('mid', 'root', 5, 0),
      task('leaf', 'mid', 5, 0),
    ]);
    await expect(
      service.incrementExecutionCount(client, task('leaf', 'mid', 5, 0)),
    ).resolves.toBe(true);
    expect([count('leaf'), count('mid'), count('root')]).toEqual([1, 1, 1]);
  });

  it('two children cannot together exceed what the parent had left', async () => {
    const { client, count } = table([
      task('root', null, 2, 0),
      task('a', 'root', 2, 0),
      task('b', 'root', 2, 0),
    ]);
    const a = task('a', 'root', 2, 0);
    const b = task('b', 'root', 2, 0);
    expect(await service.incrementExecutionCount(client, a)).toBe(true);
    expect(await service.incrementExecutionCount(client, b)).toBe(true);
    expect(await service.incrementExecutionCount(client, a)).toBe(false);
    expect(count('root')).toBe(2);
    // The refused attempt gave back the count it took on `a`.
    expect(count('a')).toBe(1);
  });

  it('a full ancestor stops an unlimited child', async () => {
    const { client, count } = table([
      task('root', null, 1, 1),
      task('child', 'root', null, 0),
    ]);
    expect(
      await service.incrementExecutionCount(
        client,
        task('child', 'root', null, 0),
      ),
    ).toBe(false);
    expect(count('child')).toBe(0);
  });

  it('a grant redemption is not refused by the ancestor count it already took', async () => {
    const { client } = table([task('root', null, 1, 1)]);
    const result = await service.evaluateFullLiveness(
      client,
      't',
      task('child', 'root', 1, 1),
      new Date('2026-10-09T00:00:00Z'),
      { executionAlreadyCounted: true },
    );
    expect(result).toMatchObject({ ok: true, root: { id: 'root' } });
  });
});
