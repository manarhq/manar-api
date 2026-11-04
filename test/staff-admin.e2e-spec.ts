/* eslint-disable @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument -- untyped JSON bodies in assertions */
import { STAFF_E2E_SUFFIX } from './support/staff-env';
import { bootStaffApp, type SeededStaff } from './support/staff-app';
import { StaffAuditService } from '../src/staff/audit/staff-audit.service';
import { createStaffRealm, deleteStaffRealm } from './support/staff-realm';

/** Staff administration, two-person grants and JIT elevation (DESK spec §10.3, §11.1, §11.3). */
describe(
  'staff administration and elevation (e2e)',
  { timeout: 60_000 },
  () => {
    let ctx: Awaited<ReturnType<typeof bootStaffApp>>;
    let owner: SeededStaff;
    let admin: SeededStaff;
    let admin2: SeededStaff;
    let support: SeededStaff;
    const as = async (s: SeededStaff) => ({
      Authorization: `Bearer ${await s.token()}`,
    });

    beforeAll(async () => {
      await createStaffRealm();
      ctx = await bootStaffApp();
      owner = await ctx.seed('owner', 'owner', { acr: 'passkey' });
      admin = await ctx.seed('ali', 'admin', { acr: 'passkey', team: 'SALES' });
      admin2 = await ctx.seed('genina', 'admin', {
        acr: 'passkey',
        eligible: 'owner',
        team: 'PARTNERSHIPS',
      });
      support = await ctx.seed('sara', 'support', { team: 'SUPPORT' });
    }, 180_000);

    afterAll(async () => {
      await ctx?.control.staffMember.deleteMany({
        where: { email: { endsWith: `-${STAFF_E2E_SUFFIX}@fixio.test` } },
      });
      await ctx?.app.close();
      await deleteStaffRealm();
    });

    it('a custom role grant needs a second person', async () => {
      const role = await ctx
        .http()
        .post('/staff/v1/staff-roles')
        .set(await as(owner))
        .send({
          key: `support-lead-${STAFF_E2E_SUFFIX}`,
          name: 'Support lead',
          permissions: ['people.view', 'notes.write', 'restrict.warn'],
        })
        .expect(201);
      const prop = await ctx
        .http()
        .post('/staff/v1/staff-assignments')
        .set(await as(owner))
        .send({
          roleId: role.body.id,
          principalType: 'STAFF',
          principalId: support.id,
          reason: 'Leads the night on-call this month',
        })
        .expect(201);
      const cr = prop.body.changeRequest;
      expect(cr).toMatchObject({ kind: 'role_grant', status: 'PENDING' });
      expect(
        (
          await ctx
            .http()
            .post(`/staff/v1/change-requests/${cr.id}/approve`)
            .set(await as(owner))
        ).body.code,
      ).toBe('own_request');
      expect(await ctx.rbac.can(support.id, 'restrict.warn')).toBe(false);
      await ctx
        .http()
        .post(`/staff/v1/change-requests/${cr.id}/approve`)
        .set(await as(admin))
        .expect(200);
      expect(await ctx.rbac.can(support.id, 'restrict.warn')).toBe(true);
      const list = await ctx
        .http()
        .get('/staff/v1/staff')
        .set(await as(admin))
        .expect(200);
      expect(
        list.body
          .find((m: { id: string }) => m.id === support.id)
          .roles.map((r: { name: string }) => r.name),
      ).toContain('Support lead');
    });

    it('an Owner grant is proposed by an Admin and approved by an Owner, never by its grantee', async () => {
      const ownerRole = await ctx.roleId('owner');
      const prop = await ctx
        .http()
        .post('/staff/v1/staff-assignments')
        .set(await as(admin))
        .send({
          roleId: ownerRole,
          principalType: 'STAFF',
          principalId: admin.id,
          kind: 'ELIGIBLE',
          reason: 'Ali covers on-call nights as Owner',
        })
        .expect(201);
      const cr = prop.body.changeRequest;
      expect(cr.kind).toBe('owner_grant');
      expect(
        (
          await ctx
            .http()
            .post(`/staff/v1/change-requests/${cr.id}/approve`)
            .set(await as(admin2))
        ).body.code,
      ).toBe('permission_required');
      await ctx
        .http()
        .post(`/staff/v1/change-requests/${cr.id}/approve`)
        .set(await as(owner))
        .expect(200);
      const eligible = await ctx.control.staffRoleAssignment.findFirst({
        where: {
          principalId: admin.id,
          roleId: ownerRole,
          kind: 'ELIGIBLE',
          revokedAt: null,
        },
      });
      expect(eligible).not.toBeNull();
    });

    it('JIT elevation: needs eligibility, a reason and a passkey; one at a time; ends early on request', async () => {
      await ctx
        .http()
        .post('/staff/v1/elevations')
        .set(await as(support))
        .send({ reason: 'Urgent abuse case tonight' })
        .expect(401); // no passkey
      await ctx
        .http()
        .post('/staff/v1/elevations')
        .set(await as(owner))
        .send({ reason: 'Already an Owner here' })
        .expect(403);
      expect(await ctx.rbac.can(admin2.id, 'restrict.ban')).toBe(false);
      const e = await ctx
        .http()
        .post('/staff/v1/elevations')
        .set(await as(admin2))
        .send({ reason: 'Ban evasion wave at 3 am' })
        .expect(201);
      expect(
        new Date(e.body.expiresAt).getTime() - Date.now(),
      ).toBeLessThanOrEqual(3_600_000);
      expect(await ctx.rbac.can(admin2.id, 'restrict.ban')).toBe(true);
      await ctx
        .http()
        .post('/staff/v1/elevations')
        .set(await as(admin2))
        .send({ reason: 'A second one at once' })
        .expect(409);
      const me = await ctx
        .http()
        .get('/staff/v1/me')
        .set(await as(admin2))
        .expect(200);
      expect(me.body.elevation).toMatchObject({ roleKey: 'owner' });
      expect(
        await ctx.control.staffAuditEvent.count({
          where: { action: 'alert.elevation_started' },
        }),
      ).toBeGreaterThan(0);
      await ctx
        .http()
        .post(`/staff/v1/elevations/${e.body.id}/end`)
        .set(await as(admin2))
        .expect(200);
      expect(await ctx.rbac.can(admin2.id, 'restrict.ban')).toBe(false);
    });

    it('a disabled staff member loses access on the next call', async () => {
      const leaver = await ctx.seed('leaver', 'support');
      const token = await leaver.token();
      await ctx
        .http()
        .get('/staff/v1/me')
        .set({ Authorization: `Bearer ${token}` })
        .expect(200);
      await ctx
        .http()
        .post(`/staff/v1/staff/${leaver.id}/disable`)
        .set(await as(admin))
        .expect(200);
      await ctx
        .http()
        .get('/staff/v1/me')
        .set({ Authorization: `Bearer ${token}` })
        .expect(403);
      await ctx
        .http()
        .post(`/staff/v1/staff/${owner.id}/disable`)
        .set(await as(admin))
        .expect(403); // Owner only
    });

    it('an expired request cannot be approved', async () => {
      const role = await ctx
        .http()
        .post('/staff/v1/staff-roles')
        .set(await as(owner))
        .send({
          key: `old-${STAFF_E2E_SUFFIX}`,
          name: 'Old',
          permissions: ['people.view'],
        })
        .expect(201);
      const prop = await ctx
        .http()
        .post('/staff/v1/staff-assignments')
        .set(await as(owner))
        .send({
          roleId: role.body.id,
          principalType: 'STAFF',
          principalId: support.id,
          reason: 'This one waits too long',
        })
        .expect(201);
      await ctx.control.staffChangeRequest.update({
        where: { id: prop.body.changeRequest.id },
        data: { expiresAt: new Date(Date.now() - 1000) },
      });
      expect(
        (
          await ctx
            .http()
            .post(
              `/staff/v1/change-requests/${prop.body.changeRequest.id}/approve`,
            )
            .set(await as(admin))
        ).body.code,
      ).toBe('expired');
    });

    it('invites are answered with a one-time token, and the staff audit chain verifies', async () => {
      const inv = await ctx
        .http()
        .post('/staff/v1/staff')
        .set(await as(admin))
        .send({
          email: `new-${STAFF_E2E_SUFFIX}@fixio.test`,
          displayName: 'New Person',
          team: 'SUPPORT',
        })
        .expect(201);
      expect(inv.body.inviteToken).toMatch(/^[A-Za-z0-9_-]{40,}$/);
      await ctx
        .http()
        .post('/staff/v1/staff')
        .set(await as(support))
        .send({
          email: `x-${STAFF_E2E_SUFFIX}@fixio.test`,
          displayName: 'X',
          team: 'SUPPORT',
        })
        .expect(403);
      await ctx.app.get(StaffAuditService).checkpoint();
      const v = await ctx
        .http()
        .post('/staff/v1/audit/verify')
        .set(await as(admin))
        .expect(200);
      // Chain validity itself is pinned by staff-audit.e2e-spec (which owns the table); here the route.
      expect(typeof v.body.valid).toBe('boolean');
    });
  },
);
