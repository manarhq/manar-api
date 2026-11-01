import { afterAll, describe, expect, it, vi } from 'vitest';
import { ControlPrismaService } from '../database/control-prisma.service';
import { DigestService } from './digest.service';

/** Real Postgres: set GROWTH_TEST_DATABASE_URL (control DB, migrations applied). */
const url = process.env.GROWTH_TEST_DATABASE_URL;
describe.skipIf(!url)('weekly digest (postgres)', () => {
  const control = new ControlPrismaService({ get: () => url } as never);
  afterAll(async () => {
    await control.membership.deleteMany({ where: { issuer: 'digest' } });
    await control.tenant.deleteMany({ where: { ownerIssuer: 'digest' } });
    await control.$disconnect();
  });

  it('sends once a week at Monday 08:00 local, and not after unsubscribe', async () => {
    await control.$connect();
    const mk = async (
      n: number,
      timezone: string | null,
      weeklyDigest = true,
    ) => {
      const t = await control.tenant.create({
        data: {
          slug: `dg-${Date.now()}-${n}`,
          name: 'd',
          kind: 'PERSONAL',
          status: 'ACTIVE',
          ownerIssuer: 'digest',
          ownerSubject: `u${n}`,
        },
      });
      return control.membership.create({
        data: {
          issuer: 'digest',
          subject: `u${n}`,
          tenantId: t.id,
          role: 'TENANT_OWNER',
          status: 'ACTIVE',
          email: `u${n}@x.io`,
          timezone,
          weeklyDigest,
        },
      });
    };
    const dubai = await mk(1, null); // default zone
    await mk(2, 'Europe/London'); // 04:00 there: not yet
    const optedOut = await mk(3, 'Asia/Dubai', false);
    const send = vi.fn().mockResolvedValue(true);
    const svc = new DigestService(
      control,
      {
        refresh: () =>
          Promise.resolve({
            actions: 10,
            askedYou: 1,
            blocked: 0,
            secretsKeptSafe: 0,
          }),
      } as never,
      { configured: true, send } as never,
      {
        verifiedMany: (people: { issuer: string; subject: string }[]) =>
          Promise.resolve(
            new Map(
              people.map((p) => [
                `${p.issuer}\n${p.subject}`,
                `${p.subject}@x.io`,
              ]),
            ),
          ),
      } as never,
      {
        get: (k: string) =>
          ({
            MANAR_LINK_SECRET: 's'.repeat(32),
            MANAR_CONSOLE_URL: 'https://api.test',
          })[k],
      } as never,
    );
    const monday = new Date('2026-11-02T04:00:00Z');
    const mine = (r: { sent: number }) => r.sent;
    // other rows in a shared test DB may exist; assert on our recipients
    await svc.sendDue(monday);
    const to = send.mock.calls.map((c) => (c[0] as { to: string }).to);
    expect(to).toContain('u1@x.io');
    expect(to).not.toContain('u2@x.io');
    expect(to).not.toContain('u3@x.io');
    const first = send.mock.calls.find(
      (c) => (c[0] as { to: string }).to === 'u1@x.io',
    )![0] as { headers: Record<string, string> };
    expect(first.headers['List-Unsubscribe']).toMatch(
      /^<https:\/\/api\.test\/public\/unsubscribe\//,
    );
    send.mockClear();
    expect(mine(await svc.sendDue(monday))).toBe(0); // same week: nothing again
    expect(send).not.toHaveBeenCalled();
    expect(await svc.unsubscribe(dubai.id)).toBe(true);
    expect(
      (await control.membership.findUnique({ where: { id: dubai.id } }))!
        .weeklyDigest,
    ).toBe(false);
    expect(optedOut.weeklyDigest).toBe(false);
  }, 30_000);
});
