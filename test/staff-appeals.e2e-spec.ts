/* eslint-disable @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-assignment -- untyped JSON bodies in assertions */
import './support/staff-env';
import { Test } from '@nestjs/testing';
import {
  FastifyAdapter,
  type NestFastifyApplication,
} from '@nestjs/platform-fastify';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { bootStaffApp, type SeededStaff } from './support/staff-app';
import { createStaffRealm, deleteStaffRealm } from './support/staff-realm';
import {
  createCustomerRealm,
  deleteCustomerRealm,
  dropCustomers,
  seedCustomer,
  type Customer,
} from './support/staff-customers';

const NOTE = 'Bulk sign-ups from one device in 40 minutes, see MNR-7KQ2XD.';

/** Appeals end to end, and the trust log in the customer's audit log (spec §9.4, §11.5). */
describe('staff appeals (e2e)', { timeout: 60_000 }, () => {
  let staff: Awaited<ReturnType<typeof bootStaffApp>>;
  let human: NestFastifyApplication;
  let admin: SeededStaff;
  let owner: SeededStaff; // passkey fresh (acr=passkey)
  let owner2: SeededStaff; // passkey fresh
  const customers: Customer[] = [];
  const as = async (s: SeededStaff) => ({
    Authorization: `Bearer ${await s.token()}`,
  });
  const api = () => request(human.getHttpServer());
  const restrict = async (
    s: SeededStaff,
    body: Record<string, unknown>,
    status?: number,
  ) => {
    const res = await staff
      .http()
      .post('/staff/v1/restrictions')
      .set(await as(s))
      .send({ category: 'spam_or_bulk_signups', note: NOTE, ...body });
    if (status) expect(res.status, JSON.stringify(res.body)).toBe(status);
    return res;
  };
  const customer = async (
    name: string,
    opts: Parameters<typeof seedCustomer>[2] = {},
  ) => {
    const c = await seedCustomer(staff.app, name, opts);
    customers.push(c);
    return c;
  };

  beforeAll(async () => {
    await createStaffRealm();
    await createCustomerRealm();
    staff = await bootStaffApp();
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
    human = moduleRef.createNestApplication<NestFastifyApplication>(
      new FastifyAdapter(),
    );
    await human.init();
    await human.getHttpAdapter().getInstance().ready();
    admin = await staff.seed('admin', 'admin', { team: 'SALES' });
    owner = await staff.seed('owner', 'owner', { acr: 'passkey', team: 'DEV' });
    owner2 = await staff.seed('owner2', 'owner', {
      acr: 'passkey',
      team: 'PARTNERSHIPS',
    });
  }, 240_000);

  afterAll(async () => {
    if (staff) {
      await dropCustomers(staff.app, customers);
      await staff.app.close();
    }
    await human?.close();
    await deleteStaffRealm();
    await deleteCustomerRealm();
  });

  const TURNSTILE = 'XXXX.DUMMY.TOKEN.XXXX';

  it('a suspended person sees why, appeals once a day, and a different Admin overturns it', async () => {
    const c = await customer('appealer');
    const r = await restrict(
      admin,
      {
        target: { type: 'ACCOUNT', id: c.accountId },
        kind: 'SUSPEND',
        duration: '30d',
      },
      201,
    );
    const auth = { Authorization: `Bearer ${await c.token()}` };
    const me = await api().get('/me/restriction').set(auth).expect(200);
    expect(me.body).toMatchObject({
      restricted: true,
      kind: 'SUSPEND',
      category: 'spam_or_bulk_signups',
    });
    expect(JSON.stringify(me.body)).not.toContain('MNR-7KQ2XD'); // the internal note never reaches them
    await api()
      .post('/me/appeals')
      .set(auth)
      .send({
        text: 'Three real clients, three workspaces.',
        turnstileToken: '',
      })
      .expect(400);
    const appeal = await api()
      .post('/me/appeals')
      .set(auth)
      .send({
        text: 'Three real clients, three workspaces.',
        turnstileToken: TURNSTILE,
      })
      .expect(201);
    expect(appeal.body.code).toMatch(/^APL-/);
    await api()
      .post('/me/appeals')
      .set(auth)
      .send({ text: 'Again', turnstileToken: TURNSTILE })
      .expect(429);

    // The Admin who suspended does not see it; someone else decides.
    const hidden = await staff
      .http()
      .get('/staff/v1/appeals')
      .set(await as(admin))
      .expect(200);
    expect(hidden.body.hiddenCount).toBeGreaterThanOrEqual(1);
    const id = (
      await staff.control.staffAppeal.findFirstOrThrow({
        where: { restrictionId: r.body.restriction.id },
      })
    ).id;
    expect(
      (
        await staff
          .http()
          .post(`/staff/v1/appeals/${id}/decide`)
          .set(await as(admin))
          .send({ outcome: 'OVERTURNED', note: 'Contracts provided by email.' })
      ).body.code,
    ).toBe('created_the_restriction');
    const queue = await staff
      .http()
      .get('/staff/v1/appeals')
      .set(await as(owner))
      .expect(200);
    expect(queue.body.items.map((a: { id: string }) => a.id)).toContain(id);
    await staff
      .http()
      .post(`/staff/v1/appeals/${id}/decide`)
      .set(await as(owner))
      .send({ outcome: 'OVERTURNED', note: 'Contracts provided by email.' })
      .expect(200);
    await api()
      .get('/workspaces')
      .set({ Authorization: `Bearer ${await c.token()}` })
      .expect(200);
  });

  it('an overturned ban opens an un-ban that another Owner approves; the customer audit log shows it all', async () => {
    const c = await customer('banappeal');
    const ban = await restrict(
      owner,
      {
        target: { type: 'ACCOUNT', id: c.accountId },
        kind: 'BAN',
        category: 'ban_evasion',
      },
      201,
    );
    const auth = { Authorization: `Bearer ${await c.token()}` };
    await api()
      .post('/me/appeals')
      .set(auth)
      .send({
        text: 'The card belongs to my employer.',
        turnstileToken: TURNSTILE,
      })
      .expect(201);
    const id = (
      await staff.control.staffAppeal.findFirstOrThrow({
        where: { restrictionId: ban.body.restriction.id },
      })
    ).id;
    const decided = await staff
      .http()
      .post(`/staff/v1/appeals/${id}/decide`)
      .set(await as(admin))
      .send({ outcome: 'OVERTURNED', note: 'Employer pays for several staff.' })
      .expect(200);
    const cr = decided.body.changeRequest;
    expect(cr.kind).toBe('unban');
    expect(
      (
        await staff
          .http()
          .post(`/staff/v1/change-requests/${cr.id}/approve`)
          .set(await as(owner))
      ).body.code,
    ).toBe('issued_the_ban');
    await staff
      .http()
      .post(`/staff/v1/change-requests/${cr.id}/approve`)
      .set(await as(owner2))
      .expect(200);
    const token = await c.token();
    await api()
      .get('/workspaces')
      .set({ Authorization: `Bearer ${token}` })
      .expect(200);
    const audit = await api()
      .get('/audit')
      .query({ limit: 50 })
      .set({
        Authorization: `Bearer ${token}`,
        'x-manar-workspace': c.tenantId,
      })
      .expect(200);
    const staffRows = (
      audit.body.items ??
      audit.body.data ??
      audit.body
    ).filter((e: { actor: { type: string } }) => e.actor?.type === 'staff');
    expect(staffRows.map((e: { eventType: string }) => e.eventType)).toEqual(
      expect.arrayContaining(['staff.restriction']),
    );
    expect(staffRows[0].actor.display).toMatch(/ · Manar /);
  });
});
