import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { EntitlementsService } from '../billing/entitlements.service';
import { ControlPrismaService } from '../database/control-prisma.service';
import { PersonalTrialService, deviceHash } from './personal-trial.service';

/** Real Postgres (the unit job's control DB with migrations applied); skipped without it. */
const url = process.env.CONTROL_DATABASE_URL;
const DAY = 86_400_000;

describe.skipIf(!url)('personal 14-day trial (postgres)', () => {
  const control = new ControlPrismaService({ get: () => url } as never);
  const ids: string[] = [];
  const emails = new Map<string, string>();
  const contact = {
    idpOf: () => Promise.resolve('email'),
    verified: (_i: string, subject: string) =>
      Promise.resolve(emails.get(subject) ?? null),
  };
  const sent: { to: string; subject: string }[] = [];
  const mailer = {
    configured: true,
    send: vi.fn((m: { to: string; subject: string }) => {
      sent.push(m);
      return Promise.resolve(true);
    }),
  };
  const cards = {
    compute: vi.fn(() => Promise.resolve({ blocked: 2 })),
  };
  const entitlements = new EntitlementsService(
    control,
    { get: () => 'https://c.example' } as never,
    { recordSafely: () => Promise.resolve() } as never,
    { getClient: () => Promise.resolve({}) } as never,
    { get: vi.fn() } as never,
  );
  const trial = new PersonalTrialService(
    control,
    entitlements,
    contact as never,
    mailer as never,
    cards as never,
    { getClient: () => Promise.resolve({}) } as never,
    { get: () => 'https://console.example' } as never,
  );
  const person = async (
    email: string | null,
    kind: 'PERSONAL' | 'COMPANY' = 'PERSONAL',
  ) => {
    const subject = `s-${randomUUID()}`;
    if (email) emails.set(subject, email);
    const t = await control.tenant.create({
      data: {
        slug: `trial-${randomUUID().slice(0, 8)}`,
        name: 'trial',
        kind,
        status: 'ACTIVE',
        ownerIssuer: 'trial-test',
        ownerSubject: subject,
      },
    });
    ids.push(t.id);
    await control.membership.create({
      data: {
        issuer: 'trial-test',
        subject,
        tenantId: t.id,
        role: 'TENANT_OWNER',
        status: 'ACTIVE',
        locale: 'ar',
      },
    });
    return t.id;
  };
  const machine = () => ({ machineId: `m-${randomUUID()}` });

  beforeAll(() => control.$connect());
  afterAll(async () => {
    await control.trialClaim.deleteMany({ where: { tenantId: { in: ids } } });
    await control.tenantEntitlement.deleteMany({
      where: { tenantId: { in: ids } },
    });
    await control.membership.deleteMany({ where: { issuer: 'trial-test' } });
    await control.tenant.deleteMany({ where: { id: { in: ids } } });
    await control.$disconnect();
  });

  it('the first approved device starts 14 days with up to 3 devices; nothing else changes', async () => {
    const t = await person(
      `a-${randomUUID()}@co-${randomUUID().slice(0, 8)}.io`,
    );
    expect(await trial.claim(t, machine())).toBe(true);
    const e = await entitlements.get(t);
    expect(e.plan).toBe('trial');
    expect(e.limits.devices).toBe(3);
    expect(e.allowance.ai).toBe(20);
    const days = (e.trialEndsAt!.getTime() - Date.now()) / DAY;
    expect(days).toBeGreaterThan(13.9);
    expect(days).toBeLessThanOrEqual(14);
    // A second device does not restart it.
    expect(await trial.claim(t, machine())).toBe(false);
  });

  it('once per device, email and person: a second workspace gets no trial', async () => {
    const m = machine();
    const email = `b-${randomUUID()}@co-${randomUUID().slice(0, 8)}.io`;
    const first = await person(email);
    expect(await trial.claim(first, m)).toBe(true);
    // Same machine, another person.
    expect(
      await trial.claim(
        await person(`c-${randomUUID()}@co-${randomUUID().slice(0, 8)}.io`),
        m,
      ),
    ).toBe(false);
    // Same email (another account), another machine.
    expect(
      await trial.claim(await person(email.toUpperCase()), machine()),
    ).toBe(false);
  });

  it('no trial for a company workspace, a throwaway mailbox or an unverified email-link account', async () => {
    expect(
      await trial.claim(await person('x@acme.io', 'COMPANY'), machine()),
    ).toBe(false);
    expect(await trial.claim(await person('x@mailinator.com'), machine())).toBe(
      false,
    );
    expect(await trial.claim(await person(null), machine())).toBe(false);
  });

  it('whoever claimed the retired launch offer has had their free period', async () => {
    const m = machine();
    const t = await person(
      `d-${randomUUID()}@co-${randomUUID().slice(0, 8)}.io`,
    );
    // The migration copies launch-offer claims with the same device hash input.
    await control.trialClaim.create({
      data: {
        tenantId: `old-${randomUUID()}`,
        kind: 'personal',
        issuer: 'old',
        subject: randomUUID(),
        deviceHash: deviceHash(m.machineId),
      },
    });
    expect(await trial.claim(t, m)).toBe(false);
    await control.trialClaim.deleteMany({ where: { issuer: 'old' } });
  });

  it("reminders on days 10, 13 and 14, each once, in the person's language", async () => {
    const t = await person(
      `e-${randomUUID()}@co-${randomUUID().slice(0, 8)}.io`,
    );
    const start = new Date(Date.now() - 9.5 * DAY);
    await trial.claim(t, machine(), start);
    const mine = () => sent.filter((s) => s.to.startsWith('e-'));
    await trial.sendDue(new Date(start.getTime() + 5 * DAY));
    expect(mine()).toHaveLength(0);
    await trial.sendDue(new Date(start.getTime() + 9.2 * DAY)); // day 10
    await trial.sendDue(new Date(start.getTime() + 9.3 * DAY)); // same day again
    expect(mine()).toHaveLength(1);
    expect(mine()[0]!.subject).toContain('تنتهي تجربتك');
    await trial.sendDue(new Date(start.getTime() + 13.5 * DAY)); // day 14: one email, not two
    expect(mine()).toHaveLength(2);
    const claim = await control.trialClaim.findUniqueOrThrow({
      where: { tenantId: t },
    });
    expect([...claim.remindersSent].sort()).toEqual([10, 13, 14]);
  });

  it('no reminder once the person upgraded', async () => {
    const t = await person(
      `f-${randomUUID()}@co-${randomUUID().slice(0, 8)}.io`,
    );
    const start = new Date(Date.now() - 10.5 * DAY);
    await trial.claim(t, machine(), start);
    await control.tenantEntitlement.update({
      where: { tenantId: t },
      data: { plan: 'pro' },
    });
    await trial.sendDue(new Date(start.getTime() + 10.2 * DAY));
    expect(sent.filter((s) => s.to.startsWith('f-'))).toHaveLength(0);
  });

  it('company trial: reminders on days 7, 12 and 14 with a one-click cancel link', async () => {
    const email = `g-${randomUUID()}@co-${randomUUID().slice(0, 8)}.io`;
    const t = await person(email, 'COMPANY');
    const tenant = await control.tenant.findUniqueOrThrow({ where: { id: t } });
    const start = new Date(Date.now() - 6.5 * DAY);
    await control.trialClaim.create({
      data: {
        tenantId: t,
        kind: 'company',
        issuer: 'trial-test',
        subject: tenant.ownerSubject!,
        cardFingerprint: `fp-${randomUUID()}`,
        claimedAt: start,
      },
    });
    await control.tenantEntitlement.create({
      data: {
        tenantId: t,
        plan: 'company_trial',
        trialEndsAt: new Date(start.getTime() + 14 * DAY),
      },
    });
    const mine = () =>
      sent.filter((s) => s.to === email) as {
        subject: string;
        text?: string;
      }[];
    await trial.sendDue(new Date(start.getTime() + 5 * DAY));
    expect(mine()).toHaveLength(0);
    await trial.sendDue(new Date(start.getTime() + 6.2 * DAY)); // day 7
    expect(mine()).toHaveLength(1);
    await trial.sendDue(new Date(start.getTime() + 11.2 * DAY)); // day 12
    await trial.sendDue(new Date(start.getTime() + 13.2 * DAY)); // day 14
    expect(mine()).toHaveLength(3);
    // In Arabic (the person's language), naming the price after the trial and the cancel link.
    expect(mine()[0]!.subject).toContain('تجربة');
    expect(mine()[0]!.text).toContain('/ar/settings/billing?trial=cancel');
    expect(mine()[0]!.text).toContain('15');
  });
});
