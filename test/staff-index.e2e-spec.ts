/* eslint-disable @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-argument -- untyped JSON bodies in assertions */
import { STAFF_E2E_SUFFIX } from './support/staff-env';
import { randomUUID } from 'node:crypto';
import { AuditService } from '../src/audit/audit.service';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { bootStaffApp, type SeededStaff } from './support/staff-app';
import { createStaffRealm, deleteStaffRealm } from './support/staff-realm';
import {
  createCustomerRealm,
  deleteCustomerRealm,
  dropCustomers,
  seedCustomer,
  type Customer,
} from './support/staff-customers';

type Json = Record<string, any>;
const body = (r: { body: unknown }) => r.body as Json;

/** Search, lists, record pages, reveals and the trust log (DESK spec §7, §8, §11.5, §12). */
describe('staff index and records (e2e)', { timeout: 60_000 }, () => {
  let ctx: Awaited<ReturnType<typeof bootStaffApp>>;
  let support: SeededStaff;
  let sales: SeededStaff;
  let auditor: SeededStaff;
  let layla: Customer;
  let omar: Customer;
  const customers: Customer[] = [];
  const as = async (s: SeededStaff) => ({
    Authorization: `Bearer ${await s.token()}`,
  });

  beforeAll(async () => {
    await createStaffRealm();
    await createCustomerRealm();
    ctx = await bootStaffApp();
    support = await ctx.seed('support', 'support', { team: 'SUPPORT' });
    sales = await ctx.seed('sales', 'sales', { team: 'SALES' });
    auditor = await ctx.seed('auditor', 'auditor');
    layla = await seedCustomer(ctx.app, 'layla', {
      email: `Layla.Haddad.${STAFF_E2E_SUFFIX}@gmail.com`,
      plan: 'pro',
    });
    omar = await seedCustomer(ctx.app, 'omar');
    customers.push(layla, omar);
  }, 180_000);

  afterAll(async () => {
    if (ctx) {
      await dropCustomers(ctx.app, customers);
      await ctx.control.account.deleteMany({
        where: { id: { in: customers.map((c) => c.accountId) } },
      });
      await ctx.app.close();
    }
    await deleteStaffRealm();
    await deleteCustomerRealm();
  });

  describe('search', () => {
    it('finds a person by exact email, a +tag or dotted Gmail variant, and a name fragment, masked', async () => {
      for (const q of [
        layla.email,
        `layla.haddad.${STAFF_E2E_SUFFIX}+promo@googlemail.com`,
        'Layla Cust',
      ]) {
        const res = await ctx
          .http()
          .get('/staff/v1/search')
          .query({ q })
          .set(await as(support))
          .expect(200);
        const hit = (body(res).people as Json[]).find(
          (p) => p.id === layla.accountId,
        );
        expect(hit, q).toBeDefined();
        expect(hit!.email).toMatch(/^l•••@gmail\.com$/);
      }
    });

    it('finds the person behind an MNR reference', async () => {
      const reference = `MNR-${randomUUID()
        .replace(/[^0-9A-HJKMNP-TV-Z]/gi, '')
        .toUpperCase()
        .replace(/[ILOU]/g, '0')
        .slice(0, 6)}`;
      await ctx.control.staffErrorReference.create({
        data: {
          reference,
          status: 500,
          route: 'GET /workspaces/me',
          issuer: process.env.AUTH_ISSUERS!,
          subject: layla.subject,
        },
      });
      const res = await ctx
        .http()
        .get('/staff/v1/search')
        .query({ q: reference.toLowerCase() })
        .set(await as(support))
        .expect(200);
      expect(body(res).references[0]).toMatchObject({
        reference,
        accountId: layla.accountId,
      });
      expect((body(res).people as Json[]).map((p) => p.id)).toContain(
        layla.accountId,
      );
    });

    it('answers odd input with empty groups, never an error', async () => {
      for (const q of [
        "'; drop table accounts; --",
        'MNR-ZZZ',
        '%_%',
        '',
        'x'.repeat(400),
      ]) {
        const res = await ctx
          .http()
          .get('/staff/v1/search')
          .query({ q })
          .set(await as(support))
          .expect(200);
        expect(body(res).people).toEqual(expect.any(Array));
      }
    });

    it('lists people with keyset pages and filters by plan', async () => {
      const page = await ctx
        .http()
        .post('/staff/v1/people/query')
        .send({ limit: 1, plan: 'pro' })
        .set(await as(support))
        .expect(200);
      expect(body(page).items).toHaveLength(1);
      expect(body(page).items[0].plan).toBe('pro');
      const all = await ctx
        .http()
        .post('/staff/v1/people/query')
        .send({ q: 'omar Cust' })
        .set(await as(support))
        .expect(200);
      expect((body(all).items as Json[]).map((p) => p.id)).toContain(
        omar.accountId,
      );
      await ctx
        .http()
        .post('/staff/v1/people/query')
        .send({ limit: 5000 })
        .set(await as(support))
        .expect(400);
    });
  });

  describe('record pages and the trust log', () => {
    it('opening a person masks PII for every role and writes one staff.record_viewed into their own audit log', async () => {
      const res = await ctx
        .http()
        .get(`/staff/v1/people/${omar.accountId}`)
        .set(await as(support))
        .expect(200);
      expect(body(res).email).toMatch(/^o•••@example\.test$/);
      expect(body(res).revealedUntil).toBeNull();
      await ctx
        .http()
        .get(`/staff/v1/people/${omar.accountId}`)
        .set(await as(support))
        .expect(200);
      const db = await ctx.app
        .get(TenantDatabaseManager)
        .getClient(omar.tenantId);
      const views = await db.auditEvent.findMany({
        where: { eventType: 'staff.record_viewed' },
      });
      expect(views).toHaveLength(1); // deduplicated for 15 minutes (AC-37)
      expect(views[0]!.actor).toMatchObject({
        type: 'staff',
        id: support.id,
        display: 'Support · Manar Support',
      });
      const verdict = await ctx.app
        .get(AuditService)
        .verifyAuditChain(db, omar.tenantId);
      expect(verdict).toEqual({ valid: true });
    });

    it('never returns session commands, prompts or secrets (spec §8.3)', async () => {
      const res = await ctx
        .http()
        .get(`/staff/v1/people/${layla.accountId}`)
        .set(await as(support))
        .expect(200);
      const keys: string[] = [];
      const walk = (v: unknown) => {
        if (!v || typeof v !== 'object') return;
        for (const [k, x] of Object.entries(v)) {
          keys.push(k.toLowerCase());
          walk(x);
        }
      };
      walk(body(res));
      for (const banned of [
        'command',
        'prompt',
        'secret',
        'toolcall',
        'params',
        'password',
      ])
        expect(keys.some((k) => k.includes(banned))).toBe(false);
    });

    it('a reveal unmasks one record for the caller only, for an hour, and is logged to both chains', async () => {
      await ctx
        .http()
        .post('/staff/v1/reveals')
        .send({
          targetType: 'ACCOUNT',
          targetId: layla.accountId,
          reason: 'short',
        })
        .set(await as(sales))
        .expect(400);
      const r = await ctx
        .http()
        .post('/staff/v1/reveals')
        .send({
          targetType: 'ACCOUNT',
          targetId: layla.accountId,
          reason: 'Customer asked for an invoice copy',
        })
        .set(await as(sales))
        .expect(201);
      expect(
        new Date(body(r).expiresAt).getTime() - Date.now(),
      ).toBeGreaterThan(59 * 60_000);
      const mine = await ctx
        .http()
        .get(`/staff/v1/people/${layla.accountId}`)
        .set(await as(sales))
        .expect(200);
      expect(body(mine).email).toBe(
        `layla.haddad.${STAFF_E2E_SUFFIX}@gmail.com`
          .replaceAll('.', '')
          .replace('@gmailcom', '@gmail.com'),
      );
      const theirs = await ctx
        .http()
        .get(`/staff/v1/people/${layla.accountId}`)
        .set(await as(support))
        .expect(200);
      expect(body(theirs).email).toMatch(/•••/);
      const db = await ctx.app
        .get(TenantDatabaseManager)
        .getClient(layla.tenantId);
      expect(
        await db.auditEvent.count({ where: { eventType: 'staff.pii_viewed' } }),
      ).toBe(1);
      expect(
        await ctx.control.staffAuditEvent.count({
          where: { action: 'staff.revealed', targetId: layla.accountId },
        }),
      ).toBe(1);
    });

    it('Auditor cannot reveal or write notes', async () => {
      await ctx
        .http()
        .post('/staff/v1/reveals')
        .send({
          targetType: 'ACCOUNT',
          targetId: omar.accountId,
          reason: 'just looking at this',
        })
        .set(await as(auditor))
        .expect(403);
      await ctx
        .http()
        .post('/staff/v1/notes')
        .send({ targetType: 'ACCOUNT', targetId: omar.accountId, body: 'x' })
        .set(await as(auditor))
        .expect(403);
    });

    it('reads the security tab from Keycloak, masked', async () => {
      const res = await ctx
        .http()
        .get(`/staff/v1/people/${omar.accountId}/security`)
        .set(await as(support))
        .expect(200);
      expect(body(res).available).toBe(true);
      expect(body(res).credentials.map((c: Json) => c.type)).toContain(
        'password',
      );
    });

    it('notes and tags round-trip and show on the page', async () => {
      await ctx
        .http()
        .post('/staff/v1/notes')
        .send({
          targetType: 'ACCOUNT',
          targetId: omar.accountId,
          body: 'Asked about the Company plan.',
        })
        .set(await as(support))
        .expect(201);
      await ctx
        .http()
        .put('/staff/v1/tags')
        .send({
          targetType: 'ACCOUNT',
          targetId: omar.accountId,
          tags: ['Enterprise-Pilot', 'vip'],
        })
        .set(await as(support))
        .expect(200);
      const page = await ctx
        .http()
        .get(`/staff/v1/people/${omar.accountId}`)
        .set(await as(support))
        .expect(200);
      expect(body(page).notes[0]).toMatchObject({
        body: 'Asked about the Company plan.',
      });
      expect(body(page).tags.sort()).toEqual(['enterprise-pilot', 'vip']);
      const tagged = await ctx
        .http()
        .post('/staff/v1/people/query')
        .send({ tag: 'vip' })
        .set(await as(support))
        .expect(200);
      expect((body(tagged).items as Json[]).map((p) => p.id)).toEqual([
        omar.accountId,
      ]);
    });

    it('an unknown id is a 404, a malformed one a 400', async () => {
      await ctx
        .http()
        .get(`/staff/v1/people/${randomUUID()}`)
        .set(await as(support))
        .expect(404);
      await ctx
        .http()
        .get('/staff/v1/people/not-a-uuid')
        .set(await as(support))
        .expect(400);
    });
  });

  it('records the DESK-forwarded address only from DESK; a spoofed header is ignored', async () => {
    await ctx
      .http()
      .get('/staff/v1/search')
      .query({ q: 'spoof-check' })
      .set(await as(support))
      .set('x-manar-client-ip', '198.51.100.66')
      .expect(200);
    const row = await ctx.control.staffAuditEvent.findFirstOrThrow({
      where: { staffId: support.id, action: { startsWith: 'http GET' } },
      orderBy: { seq: 'desc' },
    });
    expect(row.ip).not.toBe('198.51.100.66');
    expect((row.data as Json).peerIp).toBe(row.ip);
    expect((row.data as Json).q).toBe('spoof-check');
  });
});
