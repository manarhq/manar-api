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
      devices: 3,
      agents: 10,
      cloudAgents: 1,
      auditDays: 30,
    });
  });

  it('a free tenant with 3 devices cannot add a 4th', async () => {
    const { svc } = make();
    await expect(svc.assertWithin('t1', 'devices', 2)).resolves.toBeUndefined();
    const err = (await svc
      .assertWithin('t1', 'devices', 3)
      .catch((e: unknown) => e)) as PlanLimitError;
    expect(err).toBeInstanceOf(PlanLimitError);
    expect(err.getStatus()).toBe(403);
    expect(err.getResponse()).toMatchObject({
      code: 'plan_limit_reached',
      limit: 'devices',
      current: 3,
      max: 3,
      upgradeUrl: 'https://console.example/settings/billing',
    });
  });

  it('pro has unlimited agents and 10 devices', async () => {
    const { svc } = make({ plan: 'pro', status: 'active' });
    await expect(
      svc.assertWithin('t1', 'agents', 5000),
    ).resolves.toBeUndefined();
    await expect(svc.assertWithin('t1', 'devices', 10)).rejects.toBeInstanceOf(
      PlanLimitError,
    );
    expect((await svc.get('t1')).features).toContain('tls_inspection');
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
    await expect(svc.assertWithin('t1', 'devices', 2)).resolves.toBeUndefined();
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

  it('starts one company trial only', async () => {
    const { svc } = make();
    const a = await svc.startCompanyTrial('t1', { type: 'human', id: 'u' });
    expect(a.plan).toBe('company_trial');
    expect(a.limits.devices).toBe(25);
    const days = (a.trialEndsAt!.getTime() - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(29.9);
  });

  it('hides audit older than the plan window', async () => {
    const floor = await make().svc.auditSearchFloor('t1');
    const days = (Date.now() - floor!.getTime()) / 86_400_000;
    expect(days).toBeCloseTo(30, 1);
  });
});
