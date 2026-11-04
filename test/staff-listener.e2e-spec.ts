import { STAFF_E2E_SUFFIX, STAFF_E2E_TID } from './support/staff-env';
import { randomUUID } from 'node:crypto';
import { bootStaffApp, type SeededStaff } from './support/staff-app';
import {
  createStaffRealm,
  createStaffUser,
  deleteStaffRealm,
  staffToken,
} from './support/staff-realm';
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
describe('staff listener (e2e)', () => {
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

  it('binds an invited row at first sign-in, then refuses another Entra identity with that email', async () => {
    const email = `invited-${STAFF_E2E_SUFFIX}@fixio.test`;
    const row = await ctx.control.staffMember.create({
      data: { email, displayName: 'Invited Staff', team: 'SUPPORT' },
    });
    const oid = randomUUID();
    await createStaffUser({ email, oid, tid: STAFF_E2E_TID });
    await ctx
      .http()
      .get('/staff/v1/me')
      .set(await bearer(await staffToken(email)))
      .expect(200);
    expect(
      await ctx.control.staffMember.findUniqueOrThrow({
        where: { id: row.id },
      }),
    ).toMatchObject({ status: 'ACTIVE', entraOid: oid });
    // Someone else's Entra account presenting the same email address.
    const realm = `${email}`;
    await ctx.control.staffMember.update({
      where: { id: row.id },
      data: { entraOid: randomUUID() },
    });
    const res = await ctx
      .http()
      .get('/staff/v1/me')
      .set(await bearer(await staffToken(realm)))
      .expect(403);
    expect(body(res).code).toBe('staff_identity_mismatch');
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
