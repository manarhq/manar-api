/* eslint-disable @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment -- untyped JSON bodies in assertions */
import { CUSTOMER_E2E_ISSUER, STAFF_E2E_SUFFIX } from './support/staff-env';
import { randomUUID } from 'node:crypto';
import { Test } from '@nestjs/testing';
import {
  FastifyAdapter,
  type NestFastifyApplication,
} from '@nestjs/platform-fastify';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { AuditService } from '../src/audit/audit.service';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { ResignupService } from '../src/staff/restrictions/resignup.service';
import { fingerprint } from '../src/staff/restrictions/fingerprints';
import { bootStaffApp, type SeededStaff } from './support/staff-app';
import { createStaffRealm, deleteStaffRealm } from './support/staff-realm';
import {
  createCustomerRealm,
  customerToken,
  deleteCustomerRealm,
  dropCustomers,
  seedCustomer,
  type Customer,
} from './support/staff-customers';
import { adminFetch } from './support/keycloak-test-helpers';

const NOTE = 'Bulk sign-ups from one device in 40 minutes, see MNR-7KQ2XD.';

/** Warn, suspend, ban, un-ban, enforcement on customer paths and the re-signup block (spec §9). */
describe('staff restrictions (e2e)', () => {
  let staff: Awaited<ReturnType<typeof bootStaffApp>>;
  let human: NestFastifyApplication;
  let admin: SeededStaff;
  let owner: SeededStaff; // passkey fresh (acr=passkey)
  let owner2: SeededStaff; // passkey fresh
  let ownerNoPasskey: SeededStaff;
  let trustSafety: SeededStaff;
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
    ownerNoPasskey = await staff.seed('ownernp', 'owner');
    trustSafety = await staff.seed('ts', 'trust_safety', {
      team: 'TRUST_SAFETY',
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

  it('a suspension refuses the person on every customer path at once, and ends by itself', async () => {
    const c = await customer('susp');
    const token = await c.token();
    await api()
      .get('/workspaces')
      .set({ Authorization: `Bearer ${token}` })
      .expect(200);
    const r = await restrict(
      admin,
      {
        target: { type: 'ACCOUNT', id: c.accountId },
        kind: 'SUSPEND',
        duration: '1h',
      },
      201,
    );
    expect(r.body.restriction).toMatchObject({
      kind: 'SUSPEND',
      category: 'spam_or_bulk_signups',
    });
    for (const path of ['/workspaces', '/users'])
      expect(
        (
          await api()
            .get(path)
            .set({
              Authorization: `Bearer ${token}`,
              'x-manar-workspace': c.tenantId,
            })
        ).body,
      ).toMatchObject({
        code: 'account_suspended',
        category: 'spam_or_bulk_signups',
      });
    expect(r.body.restriction.effects.sessions).toEqual({ ended: true });
    // The customer's own audit log says so, by staff badge, and the chain still verifies.
    const db = await staff.app.get(TenantDatabaseManager).getClient(c.tenantId);
    const events = await db.auditEvent.findMany({
      where: { eventType: 'staff.restriction' },
    });
    expect(events[0]!.actor).toMatchObject({
      type: 'staff',
      display: 'Admin · Manar Sales',
    });
    expect(JSON.stringify(events[0]!.data)).not.toContain('MNR-7KQ2XD'); // never the internal note
    expect(
      await human.get(AuditService).verifyAuditChain(db, c.tenantId),
    ).toEqual({ valid: true });
    // Expiry is a read-time check: no job needed.
    await staff.control.staffRestriction.update({
      where: { id: r.body.restriction.id },
      data: { until: new Date(Date.now() + 1000) },
    });
    await new Promise((res) => setTimeout(res, 1200));
    await api()
      .get('/workspaces')
      .set({ Authorization: `Bearer ${await c.token()}` })
      .expect(200);
  });

  it('Trust & Safety proposes a suspension; an Admin approves it', async () => {
    const c = await customer('tsprop');
    const r = await restrict(
      trustSafety,
      {
        target: { type: 'ACCOUNT', id: c.accountId },
        kind: 'SUSPEND',
        duration: '24h',
      },
      201,
    );
    expect(r.body.changeRequest).toMatchObject({
      kind: 'suspend_proposal',
      status: 'PENDING',
    });
    // Approving needs a passkey; the Admin here has none.
    await staff
      .http()
      .post(`/staff/v1/change-requests/${r.body.changeRequest.id}/approve`)
      .set(await as(admin))
      .expect(401);
    const done = await staff
      .http()
      .post(`/staff/v1/change-requests/${r.body.changeRequest.id}/approve`)
      .set(await as(owner))
      .expect(200);
    expect(done.body.status).toBe('EXECUTED');
    expect(
      (
        await api()
          .get('/workspaces')
          .set({ Authorization: `Bearer ${await c.token()}` })
      ).status,
    ).toBe(403);
  });

  it('a ban is Owner only and needs a fresh passkey', async () => {
    const c = await customer('banned');
    const db = await staff.app.get(TenantDatabaseManager).getClient(c.tenantId);
    const hostGroup = await db.hostGroup.create({ data: { name: 'Default' } });
    await db.host.create({
      data: {
        machineId: `M-${STAFF_E2E_SUFFIX}-DEV`,
        hostname: 'LAYLA-XPS15',
        os: 'windows',
        keyFingerprint: 'k',
        keyType: 'SOFTWARE',
        registeredFromIp: '203.0.113.5',
        hostGroupId: hostGroup.id,
        ownerSubject: c.subject,
      } as never,
    });
    expect(
      (
        await restrict(admin, {
          target: { type: 'ACCOUNT', id: c.accountId },
          kind: 'BAN',
          category: 'abuse_or_attack',
        })
      ).body.code,
    ).toBe('permission_required');
    expect(
      (
        await restrict(ownerNoPasskey, {
          target: { type: 'ACCOUNT', id: c.accountId },
          kind: 'BAN',
          category: 'abuse_or_attack',
        })
      ).body.code,
    ).toBe('step_up_required');
    const r = await restrict(
      owner,
      {
        target: { type: 'ACCOUNT', id: c.accountId },
        kind: 'BAN',
        category: 'abuse_or_attack',
      },
      201,
    );
    expect(r.body.restriction.kind).toBe('BAN');
    const fps = await staff.control.staffRestrictionFingerprint.findMany({
      where: { restrictionId: r.body.restriction.id },
    });
    expect(fps.map((f) => f.kind).sort()).toEqual(['DEVICE', 'EMAIL']);

    // Re-signup with a +tag of the same address: blocked as ban evasion and recorded.
    const username = `evader-${STAFF_E2E_SUFFIX}`;
    await adminFetch(
      `/admin/realms/${CUSTOMER_E2E_ISSUER.split('/realms/')[1]}/users`,
      {
        method: 'POST',
        body: JSON.stringify({
          username,
          email: c.email.replace('@', '+again@'),
          firstName: 'E',
          lastName: 'V',
          enabled: true,
          emailVerified: true,
          credentials: [
            {
              type: 'password',
              value: 'Customer-e2e-password-1',
              temporary: false,
            },
          ],
        }),
      },
    );
    const evade = await api()
      .post('/workspaces/bootstrap')
      .set({ Authorization: `Bearer ${await customerToken(username)}` });
    expect(evade.status).toBe(403);
    expect(evade.body).toMatchObject({
      code: 'account_suspended',
      category: 'ban_evasion',
    });
    expect(
      await staff.control.staffRestrictionMatch.count({
        where: { matchedRestrictionId: r.body.restriction.id, kind: 'EMAIL' },
      }),
    ).toBe(1);

    // The same machine enrolling anywhere: refused before a certificate exists (AC-26).
    await expect(
      human
        .get(ResignupService)
        .checkDevice(`m-${STAFF_E2E_SUFFIX}-dev`, randomUUID()),
    ).rejects.toMatchObject({ response: { code: 'device_blocked' } });

    // A card of the banned account on a new paying workspace bans its owner.
    const key = process.env.RESTRICTION_FINGERPRINT_KEY!;
    await staff.control.staffRestrictionFingerprint.create({
      data: {
        restrictionId: r.body.restriction.id,
        kind: 'CARD',
        valueHash: fingerprint('CARD', 'card_fp_e2e', key),
      },
    });
    const payer = await customer('payer');
    expect(
      await human.get(ResignupService).checkCard('card_fp_e2e', payer.tenantId),
    ).toBe(r.body.restriction.code);
    expect(
      (
        await api()
          .get('/workspaces')
          .set({ Authorization: `Bearer ${await payer.token()}` })
      ).body.category,
    ).toBe('ban_evasion');
  });

  it('paying customers are warned first; an immediate ban needs a second person', async () => {
    const c = await customer('paying', { plan: 'pro' });
    await staff.control.tenantEntitlement.update({
      where: { tenantId: c.tenantId },
      data: { stripeSubscriptionId: `sub_e2e_${STAFF_E2E_SUFFIX}` },
    });
    expect(
      (
        await restrict(owner, {
          target: { type: 'ACCOUNT', id: c.accountId },
          kind: 'BAN',
          category: 'abuse_or_attack',
        })
      ).body.code,
    ).toBe('warning_required');
    await restrict(
      admin,
      {
        target: { type: 'ACCOUNT', id: c.accountId },
        kind: 'SUSPEND',
        duration: '1h',
        category: 'security_risk',
      },
      201,
    );
    const r = await restrict(
      owner,
      {
        target: { type: 'ACCOUNT', id: c.accountId },
        kind: 'BAN',
        category: 'abuse_or_attack',
        immediate: true,
      },
      201,
    );
    const cr = r.body.changeRequest;
    expect(cr.kind).toBe('immediate_restriction');
    await staff
      .http()
      .post(`/staff/v1/change-requests/${cr.id}/approve`)
      .set(await as(owner))
      .expect(403); // own request
    const done = await staff
      .http()
      .post(`/staff/v1/change-requests/${cr.id}/approve`)
      .set(await as(owner2))
      .expect(200);
    expect(done.body.status).toBe('EXECUTED');
    const ban = await staff.control.staffRestriction.findFirstOrThrow({
      where: { accountId: c.accountId, kind: 'BAN' },
    });
    // No Stripe locally: the cancellation is recorded as not done, never silently skipped.
    expect(
      (ban.effects as { cancelled: { error: string }[] }).cancelled[0]!.error,
    ).toBe('billing_not_configured');
  });

  it('un-ban needs a different Owner, who did not issue the ban', async () => {
    const c = await customer('unban');
    const ban = await restrict(
      owner,
      {
        target: { type: 'ACCOUNT', id: c.accountId },
        kind: 'BAN',
        category: 'terms_violation',
      },
      201,
    );
    const prop = await staff
      .http()
      .post(`/staff/v1/restrictions/${ban.body.restriction.id}/unban`)
      .set(await as(owner2))
      .send({ reason: 'Appeal showed the account is legitimate.' })
      .expect(201);
    const denied = await staff
      .http()
      .post(`/staff/v1/change-requests/${prop.body.id}/approve`)
      .set(await as(owner))
      .expect(403);
    expect(denied.body.code).toBe('issued_the_ban');
    await staff
      .http()
      .post(`/staff/v1/change-requests/${prop.body.id}/approve`)
      .set(await as(admin))
      .expect(401); // no passkey
    await staff.control.staffRoleAssignment.findMany(); // (Admin lacks restrict.unban.approve even with a passkey)
    const third = await staff.seed('owner3', 'owner', { acr: 'passkey' });
    await staff
      .http()
      .post(`/staff/v1/change-requests/${prop.body.id}/approve`)
      .set(await as(third))
      .expect(200);
    await api()
      .get('/workspaces')
      .set({ Authorization: `Bearer ${await c.token()}` })
      .expect(200);
  });

  it('an org suspension goes through PlatformSuspension and stops the workspace', async () => {
    const org = await staff.app.get(TenantDatabaseManager).provisionTenant({
      slug: `org-${randomUUID().slice(0, 6)}`,
      name: 'Saffron Labs',
      kind: 'COMPANY',
    });
    customers.push({ tenantId: org.id } as Customer);
    await restrict(
      admin,
      {
        target: { type: 'TENANT', id: org.id },
        kind: 'SUSPEND',
        duration: '7d',
        category: 'abuse_or_attack',
      },
      201,
    );
    expect(
      (await staff.control.tenant.findUniqueOrThrow({ where: { id: org.id } }))
        .status,
    ).toBe('SUSPENDED');
    const db = await staff.app.get(TenantDatabaseManager).getClient(org.id);
    expect(
      await db.killSwitch.findUnique({ where: { id: 'platform-suspension' } }),
    ).toMatchObject({ active: true });
    expect(await human.get(AuditService).verifyAuditChain(db, org.id)).toEqual({
      valid: true,
    });
  });

  it('banning the only Owner of a company: an Admin takes over in 7 days, else staff must choose', async () => {
    const boss = await customer('boss');
    const org = await staff.app.get(TenantDatabaseManager).provisionTenant({
      slug: `co-${randomUUID().slice(0, 6)}`,
      name: 'Haddad Studio',
      kind: 'COMPANY',
    });
    customers.push({ tenantId: org.id } as Customer);
    await staff.control.membership.create({
      data: {
        issuer: CUSTOMER_E2E_ISSUER,
        subject: boss.subject,
        tenantId: org.id,
        role: 'TENANT_OWNER',
        status: 'ACTIVE',
      },
    });
    const refused = await restrict(
      owner,
      {
        target: { type: 'ACCOUNT', id: boss.accountId },
        kind: 'BAN',
        category: 'terms_violation',
      },
      409,
    );
    expect(refused.body).toMatchObject({
      code: 'owner_plan_required',
      tenants: [org.id],
    });
    await staff.control.membership.create({
      data: {
        issuer: CUSTOMER_E2E_ISSUER,
        subject: `admin-${randomUUID()}`,
        tenantId: org.id,
        role: 'SECURITY_ADMIN',
        status: 'ACTIVE',
      },
    });
    const r = await restrict(
      owner,
      {
        target: { type: 'ACCOUNT', id: boss.accountId },
        kind: 'BAN',
        category: 'terms_violation',
      },
      201,
    );
    expect(r.body.restriction.effects.handovers).toEqual([
      { tenantId: org.id, outcome: 'admin_promoted_in_7_days' },
    ]);
    const h = await staff.control.staffOwnerHandover.findFirstOrThrow({
      where: { tenantId: org.id },
    });
    expect(h.dueAt.getTime() - Date.now()).toBeGreaterThan(6.9 * 86_400_000);
    expect(
      (await staff.control.tenant.findUniqueOrThrow({ where: { id: org.id } }))
        .status,
    ).toBe('ACTIVE');
  });
});
