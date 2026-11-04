import { describe, expect, it, vi } from 'vitest';
import { EntitlementsService } from './entitlements.service';
import { PlanLimitError } from './plan-limit.error';

type Row = Record<string, unknown> | null;

function make(row: Row = null) {
  let stored = row;
  const control = {
    tenantEntitlement: {
      findUnique: vi.fn(() => Promise.resolve(stored)),
      upsert: vi.fn((a: { create: object; update: object }) => {
        stored = {
          plan: 'free',
          status: 'active',
          ...(stored ?? a.create),
          ...a.update,
        };
        return Promise.resolve(stored);
      }),
    },
  };
  const audit = { recordSafely: vi.fn(() => Promise.resolve()) };
  const tenants = { getClient: vi.fn(() => Promise.resolve({})) };
  const config = {
    get: () => 'https://console.example',
  };
  const moduleRef = { get: vi.fn() };
  const svc = new EntitlementsService(
    control as never,
    config as never,
    audit as never,
    tenants as never,
    moduleRef as never,
  );
  return { svc, audit, control };
}

describe('EntitlementsService', () => {
  it('a tenant with no row is on the free plan', async () => {
    const e = await make().svc.get('t1');
    expect(e.plan).toBe('free');
    expect(e.limits).toEqual({
      devices: 1,
      agents: 10,
      cloudAgents: 0,
      auditDays: 30,
    });
    expect(e.allowance).toEqual({ ai: 20, cloudMinutes: 0 });
  });

  it('a free tenant with 1 device cannot add a 2nd', async () => {
    const { svc } = make();
    await expect(svc.assertWithin('t1', 'devices', 0)).resolves.toBeUndefined();
    const err = (await svc
      .assertWithin('t1', 'devices', 1)
      .catch((e: unknown) => e)) as PlanLimitError;
    expect(err).toBeInstanceOf(PlanLimitError);
    expect(err.getStatus()).toBe(403);
    expect(err.getResponse()).toMatchObject({
      code: 'plan_limit_reached',
      limit: 'devices',
      current: 1,
      max: 1,
      upgradeUrl: 'https://console.example/settings/billing',
    });
  });

  it('pro has no device cap (extra active devices are billed) and 300 AI actions', async () => {
    const { svc } = make({ plan: 'pro', status: 'active' });
    await expect(
      svc.assertWithin('t1', 'agents', 5000),
    ).resolves.toBeUndefined();
    await expect(
      svc.assertWithin('t1', 'devices', 40),
    ).resolves.toBeUndefined();
    const e = await svc.get('t1');
    expect(e.features).toContain('tls_inspection');
    expect(e.allowance).toEqual({ ai: 300, cloudMinutes: 300 });
  });

  it('the personal trial unlocks only 3 devices, then drops softly to Free', async () => {
    const live = make({
      plan: 'trial',
      status: 'active',
      trialEndsAt: new Date(Date.now() + 86_400_000),
    });
    const t = await live.svc.get('t1');
    expect(t.plan).toBe('trial');
    expect(t.limits).toMatchObject({
      devices: 3,
      cloudAgents: 0,
      auditDays: 30,
    });
    expect(t.allowance.ai).toBe(20);
    expect(t.features).not.toContain('tls_inspection');
    await expect(
      live.svc.assertWithin('t1', 'devices', 3),
    ).rejects.toBeInstanceOf(PlanLimitError);
    const ended = make({
      plan: 'trial',
      status: 'active',
      trialEndsAt: new Date(Date.now() - 1000),
    });
    const f = await ended.svc.get('t1');
    expect(f.plan).toBe('free');
    expect(f.status).toBe('active');
    expect(f.limits.devices).toBe(1);
  });

  it('a dispute freezes paid features to Free limits, keeping the plan name', async () => {
    const { svc } = make({ plan: 'pro', status: 'frozen' });
    const e = await svc.get('t1');
    expect(e.plan).toBe('pro');
    expect(e.status).toBe('frozen');
    expect(e.limits.devices).toBe(1);
    expect(e.features).toEqual([]);
    expect(e.allowance.ai).toBe(20);
  });

  it('company has no Enterprise-only features and no device cap', async () => {
    const { svc } = make({ plan: 'company', status: 'active' });
    const e = await svc.get('t1');
    for (const f of ['hub', 'air_gapped', 'gov', 'tpm', 'compliance_packs'])
      expect(e.features).not.toContain(f);
    await expect(
      svc.assertWithin('t1', 'devices', 400),
    ).resolves.toBeUndefined();
  });

  it('a lapsed trial is read-only and cannot add anything', async () => {
    const { svc } = make({
      plan: 'company_trial',
      status: 'active',
      trialEndsAt: new Date(Date.now() - 1000),
    });
    expect((await svc.get('t1')).status).toBe('read_only');
    await expect(svc.assertWithin('t1', 'agents', 0)).rejects.toBeInstanceOf(
      PlanLimitError,
    );
  });

  it('downgrade to free keeps the count but refuses new devices over the cap', async () => {
    const { svc } = make({ plan: 'pro', status: 'active' });
    // 8 devices enrolled on Pro; the plan drops to free.
    await svc.change(
      't1',
      { plan: 'free' },
      { type: 'system', id: 'stripe' },
      'stripe',
    );
    await expect(svc.assertWithin('t1', 'devices', 8)).rejects.toBeInstanceOf(
      PlanLimitError,
    );
    // Nothing removes the 8; below the cap enrolment works again.
    await expect(svc.assertWithin('t1', 'devices', 0)).resolves.toBeUndefined();
  });

  it('audits billing.plan.changed only when the plan moves', async () => {
    const { svc, audit } = make();
    await svc.change(
      't1',
      { stripeCustomerId: 'cus_1' },
      { type: 'system', id: 's' },
      'x',
    );
    expect(audit.recordSafely).not.toHaveBeenCalled();
    await svc.change('t1', { plan: 'pro' }, { type: 'system', id: 's' }, 'x');
    expect(audit.recordSafely).toHaveBeenCalledWith(
      expect.anything(),
      't1',
      expect.objectContaining({
        eventType: 'billing.plan.changed',
        data: { from: 'free', to: 'pro', source: 'x' },
      }),
    );
  });

  it('hides audit older than the plan window', async () => {
    const floor = await make().svc.auditSearchFloor('t1');
    const days = (Date.now() - floor!.getTime()) / 86_400_000;
    expect(days).toBeCloseTo(30, 1);
  });

  it('withinLimit: N+1 parallel creates against a cap of N let exactly N through', async () => {
    const { svc } = make({
      plan: 'trial',
      status: 'active',
      trialEndsAt: new Date(Date.now() + 86_400_000),
    }); // 3 devices
    const rows: number[] = [];
    // Stand-in for Postgres: pg_advisory_xact_lock queues transactions, released at commit.
    let tail: Promise<void> = Promise.resolve();
    const client = {
      $transaction: async (fn: (tx: unknown) => Promise<unknown>) => {
        let release!: () => void;
        const mine = new Promise<void>((r) => (release = r));
        const prev = tail;
        tail = mine;
        const tx = {
          $executeRaw: async (strings: TemplateStringsArray) => {
            expect(strings.join('?')).toContain('pg_advisory_xact_lock');
            await prev;
          },
        };
        try {
          return await fn(tx);
        } finally {
          release();
        }
      },
    };
    const attempt = (n: number) =>
      svc.withinLimit(
        't1',
        'devices',
        client as never,
        async () => {
          await new Promise((r) => setTimeout(r, 5)); // widen the race window
          return rows.length;
        },
        async () => {
          await new Promise((r) => setTimeout(r, 5));
          rows.push(n);
          return n;
        },
      );
    const results = await Promise.allSettled([0, 1, 2, 3].map(attempt));
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(3);
    const failed = results.filter((r) => r.status === 'rejected');
    expect(failed).toHaveLength(1);
    expect((failed[0] as PromiseRejectedResult).reason).toBeInstanceOf(
      PlanLimitError,
    );
    expect(rows).toHaveLength(3);
  });
});
