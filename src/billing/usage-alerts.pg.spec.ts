import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ControlPrismaService } from '../database/control-prisma.service';
import { PLAN_TABLE, monthOf } from './plans';
import { UsageAlertsService } from './usage-alerts.service';

/** Real Postgres (the unit job's control DB with migrations applied); skipped without it. */
const url = process.env.CONTROL_DATABASE_URL;

describe.skipIf(!url)('usage alerts (postgres)', () => {
  const control = new ControlPrismaService({ get: () => url } as never);
  const tenantId = `alerts-${randomUUID()}`;
  const send = vi.fn((m: unknown) => {
    void m;
    return Promise.resolve(true);
  });
  const svc = new UsageAlertsService(
    control,
    {
      get: () =>
        Promise.resolve({ plan: 'free', status: 'active', ...PLAN_TABLE.free }),
    } as never,
    { configured: true, send } as never,
    {
      verified: (_i: string, subject: string) =>
        Promise.resolve(`${subject}@acme.io`),
    } as never,
    { get: () => 'https://console.example' } as never,
  );
  const findMany = vi.spyOn(control.membership, 'findMany');

  beforeAll(async () => {
    await control.$connect();
    // One owner per workspace, named after it, so other files' rows never mix in.
    findMany.mockImplementation(((args: { where: { tenantId: string } }) =>
      Promise.resolve([
        { issuer: 'i', subject: args.where.tenantId, locale: 'en' },
      ])) as never);
  });
  afterAll(async () => {
    await control.usageMonth.deleteMany({ where: { tenantId } });
    await control.$disconnect();
  });

  it('sends the highest new step once, records the lower ones, and never repeats', async () => {
    await control.usageMonth.create({
      data: { tenantId, month: monthOf(), aiUsed: 17 },
    });
    await svc.sendDue();
    const mine = () =>
      send.mock.calls.filter(
        (c) => (c[0] as { to: string }).to === `${tenantId}@acme.io`,
      );
    expect(mine()).toHaveLength(1);
    expect((mine()[0]![0] as { subject: string }).subject).toContain('80%');
    await svc.sendDue();
    expect(mine()).toHaveLength(1);
    await control.usageMonth.update({
      where: { tenantId_month: { tenantId, month: monthOf() } },
      data: { aiUsed: 20 },
    });
    await svc.sendDue();
    expect(mine()).toHaveLength(2);
    const m = await control.usageMonth.findUniqueOrThrow({
      where: { tenantId_month: { tenantId, month: monthOf() } },
    });
    expect([...m.alertsSent].sort()).toEqual(['ai:100', 'ai:50', 'ai:80']);
  });

  it('a failed send gives the alert back for the next tick', async () => {
    const t2 = `alerts-${randomUUID()}`;
    await control.usageMonth.create({
      data: { tenantId: t2, month: monthOf(), aiUsed: 10 },
    });
    let failOnce = true;
    send.mockImplementation((m: unknown) => {
      const mine = (m as { to: string }).to === `${t2}@acme.io`;
      if (mine && failOnce) {
        failOnce = false;
        return Promise.resolve(false);
      }
      return Promise.resolve(true);
    });
    await svc.sendDue();
    let m = await control.usageMonth.findUniqueOrThrow({
      where: { tenantId_month: { tenantId: t2, month: monthOf() } },
    });
    expect(m.alertsSent).not.toContain('ai:50');
    await svc.sendDue();
    m = await control.usageMonth.findUniqueOrThrow({
      where: { tenantId_month: { tenantId: t2, month: monthOf() } },
    });
    expect(m.alertsSent).toContain('ai:50');
    await control.usageMonth.deleteMany({ where: { tenantId: t2 } });
  });
});
