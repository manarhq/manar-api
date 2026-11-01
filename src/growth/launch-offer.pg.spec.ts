import { afterAll, describe, expect, it } from 'vitest';
import { ControlPrismaService } from '../database/control-prisma.service';
import { LaunchOfferService } from './launch-offer.service';

/**
 * Real Postgres race test: set GROWTH_TEST_DATABASE_URL to a control database with the migrations
 * applied (skipped otherwise). 40 personal workspaces register a device at once for 7 slots.
 */
const url = process.env.GROWTH_TEST_DATABASE_URL;
describe.skipIf(!url)('launch offer slots (postgres)', () => {
  const control = new ControlPrismaService({
    get: () => url,
  } as never);
  afterAll(async () => {
    await control.launchOfferClaim.deleteMany({});
    await control.membership.deleteMany({ where: { issuer: 'race' } });
    await control.tenant.deleteMany({ where: { ownerIssuer: 'race' } });
    await control.$disconnect();
  });

  it('never hands out more than the slots, whatever the interleaving', async () => {
    await control.$connect();
    await control.launchOfferClaim.deleteMany({});
    const ids: string[] = [];
    for (let i = 0; i < 40; i++) {
      const t = await control.tenant.create({
        data: {
          slug: `race-${Date.now()}-${i}`,
          name: 'race',
          kind: 'PERSONAL',
          status: 'ACTIVE',
          ownerIssuer: 'race',
          ownerSubject: `u${i}`,
        },
      });
      await control.membership.create({
        data: {
          issuer: 'race',
          subject: `u${i}`,
          tenantId: t.id,
          role: 'TENANT_OWNER',
          status: 'ACTIVE',
          email: `u${i}@x.io`,
        },
      });
      ids.push(t.id);
    }
    const svc = new LaunchOfferService(
      control,
      { get: (k: string) => ({ LAUNCH_OFFER_SLOTS: 7 })[k] } as never,
      {
        configured: true,
        price: () => 'price_x',
        client: () => ({
          subscriptions: {
            create: () => Promise.resolve({ id: 'sub_x' }),
            list: () => Promise.resolve({ data: [] }),
          },
        }),
      } as never,
      { ensureCustomer: () => Promise.resolve('cus_x') } as never,
      { change: () => Promise.resolve() } as never,
      { record: () => Promise.resolve() } as never,
      {
        idpOf: () => Promise.resolve('github'),
        verified: () => Promise.resolve(null),
      } as never,
    );
    const got = await Promise.all(
      ids.map((id, i) => svc.claim(id, { machineId: `machine-${i}` })),
    );
    expect(got.filter(Boolean)).toHaveLength(7);
    expect(await control.launchOfferClaim.count()).toBe(7);
    // a second device from the same person does not take another slot
    const winner = ids[got.indexOf(true)]!;
    expect(await svc.claim(winner, { machineId: 'another-machine' })).toBe(
      false,
    );
  }, 30_000);
});
