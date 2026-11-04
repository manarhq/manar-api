import { STAFF_E2E_SUFFIX, STAFF_E2E_TID } from './support/staff-env';
import { randomUUID } from 'node:crypto';
import { bootStaffApp, type SeededStaff } from './support/staff-app';
import {
  createStaffRealm,
  createStaffUser,
  deleteStaffRealm,
  staffToken,
} from './support/staff-realm';
import { newInviteToken } from '../src/staff/auth/staff-invites';
import { OpenFgaClientService } from '../src/authorization/openfga-client.service';

interface Body {
  staff: { id: string; badge: string };
  roles: { key: string }[];
  permissions: string[];
  reference: string;
  code?: string;
  reason?: string;
}
const body = (r: { body: unknown }) => r.body as Body;

/** The staff listener's guard and /me routes against a real Keycloak realm (DESK spec §16). */
describe('staff listener (e2e)', { timeout: 60_000 }, () => {
  let ctx: Awaited<ReturnType<typeof bootStaffApp>>;
  let owner: SeededStaff;
  let auditor: SeededStaff;
  const bearer = async (s: SeededStaff | string) => ({
    Authorization: `Bearer ${typeof s === 'string' ? s : await s.token()}`,
  });

  beforeAll(async () => {
    await createStaffRealm();
    ctx = await bootStaffApp();
    owner = await ctx.seed('owner', 'owner', { team: 'DEV' });
    auditor = await ctx.seed('auditor', 'auditor');
  }, 120_000);

  afterAll(async () => {
    await ctx?.control.staffMember.deleteMany({
      where: { email: { endsWith: `-${STAFF_E2E_SUFFIX}@fixio.test` } },
    });
    await ctx?.app.close();
    await deleteStaffRealm();
  });

  it('returns the caller, their roles and their badge', async () => {
    const res = await ctx
      .http()
      .get('/staff/v1/me')
      .set(await bearer(owner))
      .expect(200);
    expect(body(res).staff).toMatchObject({
      id: owner.id,
      badge: 'Owner · Manar Dev',
    });
    expect(body(res).roles.map((r) => r.key)).toContain('owner');
  });

  it('lists permissions for UI gating', async () => {
    const o = await ctx
      .http()
      .get('/staff/v1/me/permissions')
      .set(await bearer(owner))
      .expect(200);
    expect(body(o).permissions).toContain('restrict.ban');
    const a = await ctx
      .http()
      .get('/staff/v1/me/permissions')
      .set(await bearer(auditor))
      .expect(200);
    expect(body(a).permissions).not.toContain('restrict.ban');
    expect(body(a).permissions).toContain('staff.audit.view');
  });

  it('refuses a token without the Entra claims, from another tenant, or for a stranger', async () => {
    const local = `local-${STAFF_E2E_SUFFIX}@fixio.test`;
    await createStaffUser({
      email: local,
      oid: randomUUID(),
      tid: STAFF_E2E_TID,
      idp: 'password',
    });
    await ctx
      .http()
      .get('/staff/v1/me')
      .set(await bearer(await staffToken(local)))
      .expect(401);
    const foreign = `foreign-${STAFF_E2E_SUFFIX}@fixio.test`;
    await createStaffUser({
      email: foreign,
      oid: randomUUID(),
      tid: randomUUID(),
    });
    await ctx
      .http()
      .get('/staff/v1/me')
      .set(await bearer(await staffToken(foreign)))
      .expect(401);
    const stranger = `stranger-${STAFF_E2E_SUFFIX}@fixio.test`;
    await createStaffUser({
      email: stranger,
      oid: randomUUID(),
      tid: STAFF_E2E_TID,
    });
    const res = await ctx
      .http()
      .get('/staff/v1/me')
      .set(await bearer(await staffToken(stranger)))
      .expect(403);
    expect(body(res).reference).toMatch(/^MNR-/);
    await ctx.http().get('/staff/v1/me').expect(401);
  });

  describe('invites bind by a stable id, never by email (security review, 4 Nov)', () => {
    const invite = async (name: string) => {
      const email = `${name}-${STAFF_E2E_SUFFIX}@fixio.test`;
      const { token, hash, expiresAt } = newInviteToken();
      const row = await ctx.control.staffMember.create({
        data: {
          email,
          displayName: 'Invited Staff',
          team: 'SUPPORT',
          inviteTokenHash: hash,
          inviteExpiresAt: expiresAt,
        },
      });
      return { email, token, row };
    };

    it('an email claim alone does not bind: the person must present the invite token', async () => {
      const { email, token, row } = await invite('invited');
      const oid = randomUUID();
      await createStaffUser({ email, oid, tid: STAFF_E2E_TID });
      const t = await staffToken(email);
      await ctx
        .http()
        .get('/staff/v1/me')
        .set(await bearer(t))
        .expect(403);
      expect(
        (
          await ctx.control.staffMember.findUniqueOrThrow({
            where: { id: row.id },
          })
        ).status,
      ).toBe('INVITED');
      await ctx
        .http()
        .post('/staff/v1/invites/claim')
        .set(await bearer(t))
        .send({ token })
        .expect(200);
      expect(
        await ctx.control.staffMember.findUniqueOrThrow({
          where: { id: row.id },
        }),
      ).toMatchObject({ status: 'ACTIVE', entraOid: oid });
      await ctx
        .http()
        .get('/staff/v1/me')
        .set(await bearer(t))
        .expect(200);
    });

    it('a second person with the same email claim gets nothing, with or without the token', async () => {
      const { email, token } = await invite('twin');
      await createStaffUser({ email, oid: randomUUID(), tid: STAFF_E2E_TID });
      const first = await staffToken(email);
      await ctx
        .http()
        .post('/staff/v1/invites/claim')
        .set(await bearer(first))
        .send({ token })
        .expect(200);
      // Another Entra account carrying the same email address (a second Keycloak user here).
      const twinUser = `twin-account-${STAFF_E2E_SUFFIX}`;
      await createStaffUser({
        email,
        username: twinUser,
        oid: randomUUID(),
        tid: STAFF_E2E_TID,
      });
      const twin = await staffToken(twinUser);
      await ctx
        .http()
        .get('/staff/v1/me')
        .set(await bearer(twin))
        .expect(403);
      const res = await ctx
        .http()
        .post('/staff/v1/invites/claim')
        .set(await bearer(twin))
        .send({ token })
        .expect(403);
      expect(body(res).code).toBe('invite_invalid');
    });

    it('two concurrent claims of one invite: exactly one wins', async () => {
      const { email, token, row } = await invite('race');
      await createStaffUser({ email, oid: randomUUID(), tid: STAFF_E2E_TID });
      const t = await staffToken(email);
      const results = await Promise.all(
        Array.from({ length: 5 }, () =>
          ctx
            .http()
            .post('/staff/v1/invites/claim')
            .set({ Authorization: `Bearer ${t}` })
            .send({ token }),
        ),
      );
      expect(results.filter((r) => r.status === 200)).toHaveLength(1);
      expect(results.filter((r) => r.status === 403)).toHaveLength(4);
      expect(
        (
          await ctx.control.staffMember.findUniqueOrThrow({
            where: { id: row.id },
          })
        ).inviteTokenHash,
      ).toBeNull();
    });
  });

  it('refuses a disabled staff member at once', async () => {
    const s = await ctx.seed('leaver', 'support');
    const token = await s.token();
    await ctx
      .http()
      .get('/staff/v1/me')
      .set(await bearer(token))
      .expect(200);
    await ctx.control.staffMember.update({
      where: { id: s.id },
      data: { status: 'DISABLED' },
    });
    await ctx
      .http()
      .get('/staff/v1/me')
      .set(await bearer(token))
      .expect(403);
  });

  it('answers 503 when OpenFGA cannot answer (fail closed)', async () => {
    const fga = ctx.app.get(OpenFgaClientService);
    const spy = vi
      .spyOn(fga, 'check')
      .mockRejectedValue(new Error('openfga down'));
    try {
      const res = await ctx
        .http()
        .get('/staff/v1/me/permissions')
        .set(await bearer(owner))
        .expect(503);
      expect(body(res).reason ?? body(res).code).toBe(
        'enforcement_dependency_unavailable',
      );
      // Every 5xx is kept by its MNR reference for staff lookup (AC-11).
      await new Promise((r) => setTimeout(r, 300));
      const stored = await ctx.control.staffErrorReference.findUnique({
        where: { reference: body(res).reference },
      });
      expect(stored).toMatchObject({ status: 503, subject: owner.id });
    } finally {
      spy.mockRestore();
    }
  });
});
