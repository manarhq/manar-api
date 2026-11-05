import { describe, expect, it, vi } from 'vitest';
import {
  FRICTION_BUDGET,
  dayRange,
  numbers,
  overBudget,
  promptsPerDeveloperPerDay,
  type FrictionRow,
} from './friction';
import { FrictionService } from './friction.service';
import { parseDays } from './friction.controller';
import { registry } from '../metrics/metrics';

const row = (over: Partial<FrictionRow> = {}): FrictionRow => ({
  day: new Date('2026-11-05T00:00:00Z'),
  subject: 'u1',
  prompts: 0,
  approvals: 0,
  denies: 0,
  expired: 0,
  deniedLaterApproved: 0,
  answered: 0,
  answerMs: 0,
  blockedMs: 0,
  ...over,
});

describe('friction numbers', () => {
  it('sums rows, averages answer time over answered prompts, and counts blocked minutes', () => {
    const n = numbers([
      row({
        prompts: 4,
        approvals: 3,
        denies: 1,
        answered: 4,
        answerMs: 20_000,
        blockedMs: 90_000,
      }),
      row({
        subject: 'u2',
        prompts: 2,
        expired: 1,
        deniedLaterApproved: 1,
        answered: 1,
        answerMs: 10_000,
        blockedMs: 150_000,
      }),
    ]);
    expect(n).toEqual({
      prompts: 6,
      approvals: 3,
      denies: 1,
      expired: 1,
      deniedLaterApproved: 1,
      answered: 5,
      avgAnswerSeconds: 6,
      blockedMinutes: 4,
    });
    expect(numbers([]).avgAnswerSeconds).toBe(0);
  });
  it('the budget is 5 prompts per developer per day, strictly over', () => {
    expect(FRICTION_BUDGET).toBe(5);
    expect(promptsPerDeveloperPerDay(70, 2, 7)).toBe(5);
    expect(overBudget(5)).toBe(false);
    expect(overBudget(5.1)).toBe(true);
    // quiet developers lower the average; nobody enrolled does not divide by zero
    expect(promptsPerDeveloperPerDay(70, 4, 7)).toBe(2.5);
    expect(promptsPerDeveloperPerDay(7, 0, 7)).toBe(1);
  });
  it('a window is whole UTC days ending today', () => {
    const r = dayRange(new Date('2026-11-05T23:59:00Z'), 3);
    expect(r.map((d) => d.toISOString().slice(0, 10))).toEqual([
      '2026-11-03',
      '2026-11-04',
      '2026-11-05',
    ]);
  });
});

describe('over-budget alert', () => {
  function svc(avgPrompts: number[], finds?: { n: number }) {
    const tenants = avgPrompts.map((_, i) => ({
      id: `t${i}`,
      slug: `ws-${i}`,
      name: `W${i}`,
      kind: 'COMPANY',
    }));
    const control = {
      tenant: {
        findMany: () => {
          if (finds) finds.n++;
          return Promise.resolve(tenants);
        },
      },
    };
    const manager = {
      getClient: (id: string) => {
        const i = Number(id.slice(1));
        return Promise.resolve({
          frictionDaily: {
            findMany: () => Promise.resolve([row({ prompts: avgPrompts[i]! })]),
          },
          host: {
            findMany: () => Promise.resolve([{ ownerSubject: 'u1' }]),
          },
        });
      },
    };
    const s = new FrictionService(control as never, manager as never);
    // the rollup itself is covered against Postgres; here the table is already current
    vi.spyOn(s, 'refresh').mockResolvedValue(undefined);
    return s;
  }
  it('flags workspaces above 5 per developer per day, worst first', async () => {
    const out = await svc([20, 40, 70]).staff(7);
    expect(
      out.map((w) => [w.slug, w.avgPromptsPerDeveloperPerDay, w.overBudget]),
    ).toEqual([
      ['ws-2', 10, true],
      ['ws-1', 5.7, true],
      ['ws-0', 2.9, false],
    ]);
  });
  it('the staff rollup is cached for 10 minutes per window, so Desk polling does not walk every workspace', async () => {
    const finds = { n: 0 };
    const s = svc([20, 70], finds);
    const t = new Date('2026-11-05T10:00:00Z');
    const a = await s.staff(7, t);
    expect(await s.staff(7, new Date(t.getTime() + 9 * 60_000))).toBe(a);
    expect(finds.n).toBe(1);
    await s.staff(14, t); // another window is its own entry
    expect(finds.n).toBe(2);
    await s.staff(7, new Date(t.getTime() + 11 * 60_000));
    expect(finds.n).toBe(3);
  });
  it('scan warns once per workspace over budget, sets the gauge, and waits 6 hours', async () => {
    const s = svc([20, 70]);
    const warn = vi
      .spyOn(
        (s as unknown as { logger: { warn: (m: string) => void } }).logger,
        'warn',
      )
      .mockImplementation(() => undefined);
    const now = new Date('2026-11-05T10:00:00Z');
    expect(await s.scan(now)).toBe(1);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0]?.[0])).toContain('ws-1');
    expect(
      await registry.getSingleMetricAsString(
        'manar_friction_workspaces_over_budget',
      ),
    ).toContain(
      'manar_friction_workspaces_over_budget{service_name="manar-api"} 1',
    );
    expect(await s.scan(new Date(now.getTime() + 3_600_000))).toBe(0);
    expect(await s.scan(new Date(now.getTime() + 7 * 3_600_000))).toBe(1);
  });
});

describe('days query', () => {
  it('is 1 to 90 with a default', () => {
    expect([
      parseDays(undefined),
      parseDays('0'),
      parseDays('500'),
      parseDays('x'),
      parseDays('30'),
    ]).toEqual([14, 1, 90, 14, 30]);
    expect(parseDays(undefined, 7)).toBe(7);
  });
});
