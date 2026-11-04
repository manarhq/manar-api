import 'dotenv/config';
import { onTestFinished, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { CheckpointSigner } from '../src/audit/checkpoint/checkpoint-signer';
import { OpenFgaClientService } from '../src/authorization/openfga-client.service';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { OpenBaoKvClient } from '../src/openbao/openbao-kv.client';
import { StaffAuditService } from '../src/staff/audit/staff-audit.service';
import {
  StaffRbacService,
  assigneeTuple,
} from '../src/staff/rbac/staff-rbac.service';

/** Staff RBAC against real Postgres and a fresh OpenFGA store (DESK spec §10, AC-29, AC-31). */
describe('staff RBAC (e2e)', () => {
  const env: Record<string, unknown> = {
    ...process.env,
    OPENFGA_STORE_NAME: `staff-rbac-e2e-${randomUUID().slice(0, 8)}`,
    OPENFGA_CHECK_TIMEOUT_MS: 2000,
    OPENFGA_CACHE_TTL_MS: 3000,
  };
  const config = { get: (k: string) => env[k] } as never;
  const control = new ControlPrismaService(config);
  const fga = new OpenFgaClientService(config);
  const kv = new OpenBaoKvClient(config);
  const audit = new StaffAuditService(
    control,
    new CheckpointSigner(kv),
    kv,
    `rbac-e2e-${randomUUID()}`,
  );
  const rbac = new StaffRbacService(control, fga, audit);
  const suffix = randomUUID().slice(0, 8);
  let owner: string;
  let admin: string;
  let support: string;
  const roleId = async (key: string) =>
    (await control.staffRole.findUniqueOrThrow({ where: { key } })).id;
  const staff = (name: string) =>
    control.staffMember
      .create({
        data: {
          email: `${name}-${suffix}@fixio.test`,
          displayName: name,
          team: 'DEV',
          status: 'ACTIVE',
        },
      })
      .then((s) => s.id);

  beforeAll(async () => {
    await fga.onModuleInit();
    await rbac.ensureBuiltInRoles();
    owner = await staff('owner');
    admin = await staff('admin');
    support = await staff('support');
    await rbac.grant({
      roleId: await roleId('owner'),
      principalType: 'STAFF',
      principalId: owner,
      kind: 'ACTIVE',
      grantedBy: 'system',
    });
    await rbac.grant({
      roleId: await roleId('admin'),
      principalType: 'STAFF',
      principalId: admin,
      kind: 'ACTIVE',
      grantedBy: 'system',
    });
    // This store is new; align it with whatever earlier runs left in Postgres.
    await rbac.reconcile({ dryRun: false });
  }, 60_000);

  afterAll(async () => {
    const ids = [owner, admin, support];
    await control.staffRoleAssignment.deleteMany({
      where: { OR: [{ principalId: { in: ids } }, { grantedBy: { in: ids } }] },
    });
    await control.staffGroup.deleteMany({
      where: { name: { endsWith: suffix } },
    });
    await control.staffRole.deleteMany({
      where: { key: { endsWith: suffix } },
    });
    await control.staffMember.deleteMany({ where: { id: { in: ids } } });
    await control.$disconnect();
  });

  it('a grant gives the role permissions at once; a revoke removes them at once', async () => {
    expect(await rbac.can(support, 'people.view')).toBe(false);
    const a = await rbac.grant({
      roleId: await roleId('support'),
      principalType: 'STAFF',
      principalId: support,
      kind: 'ACTIVE',
      grantedBy: owner,
    });
    expect(await rbac.can(support, 'people.view')).toBe(true);
    expect(await rbac.can(support, 'restrict.ban')).toBe(false);
    await rbac.revoke(a.id, owner);
    expect(await rbac.can(support, 'people.view')).toBe(false);
  });

  it('an ELIGIBLE assignment alone gives nothing', async () => {
    await rbac.grant({
      roleId: await roleId('owner'),
      principalType: 'STAFF',
      principalId: admin,
      kind: 'ELIGIBLE',
      grantedBy: owner,
    });
    expect(await rbac.can(admin, 'restrict.ban')).toBe(false);
  });

  it('a timed grant ends at its expiry with no job running', async () => {
    const a = await rbac.grant({
      roleId: await roleId('auditor'),
      principalType: 'STAFF',
      principalId: support,
      kind: 'ACTIVE',
      expiresAt: new Date(Date.now() + 1500),
      grantedBy: owner,
    });
    expect(await rbac.can(support, 'staff.audit.view')).toBe(true);
    await new Promise((r) => setTimeout(r, 1700));
    expect(await rbac.can(support, 'staff.audit.view')).toBe(false);
    await rbac.revoke(a.id, owner);
  });

  it('an OpenFGA failure on grant leaves no active Postgres row (fail closed)', async () => {
    const broken = new OpenFgaClientService(config);
    const brokenRbac = new StaffRbacService(control, broken, audit); // never initialised: every call throws
    const before = await control.staffRoleAssignment.count({
      where: { principalId: support, revokedAt: null },
    });
    await expect(
      brokenRbac.grant({
        roleId: await roleId('billing'),
        principalType: 'STAFF',
        principalId: support,
        kind: 'ACTIVE',
        grantedBy: owner,
      }),
    ).rejects.toThrow();
    expect(
      await control.staffRoleAssignment.count({
        where: { principalId: support, revokedAt: null },
      }),
    ).toBe(before);
    await expect(brokenRbac.can(owner, 'people.view')).rejects.toThrow();
  });

  it('custom roles refuse Owner-only keys and keys the editor lacks', async () => {
    await expect(
      rbac.saveCustomRole({
        key: `bad-${suffix}`,
        name: 'Bad',
        permissions: ['people.view', 'restrict.ban'],
        by: owner,
      }),
    ).rejects.toMatchObject({ response: { code: 'owner_only_permission' } });
    // Admin lacks restrict.unban.propose, so it cannot put it in a role.
    await expect(
      rbac.saveCustomRole({
        key: `lead-${suffix}`,
        name: 'Lead',
        permissions: ['people.view', 'restrict.unban.propose'],
        by: admin,
      }),
    ).rejects.toMatchObject({ response: { code: 'cannot_grant_unheld' } });
  });

  it('a new version of a custom role removes a dropped permission from every holder, and groups pass a built-in role on', async () => {
    const role = await rbac.saveCustomRole({
      key: `lead2-${suffix}`,
      name: 'Lead',
      permissions: ['people.view', 'notes.write'],
      by: owner,
    });
    const held = await rbac.grant({
      roleId: role.id,
      principalType: 'STAFF',
      principalId: support,
      kind: 'ACTIVE',
      grantedBy: owner,
    });
    expect(await rbac.can(support, 'notes.write')).toBe(true);
    await rbac.saveCustomRole({
      roleId: role.id,
      key: role.key,
      name: 'Lead',
      permissions: ['people.view'],
      by: owner,
    });
    expect(await rbac.can(support, 'notes.write')).toBe(false);
    expect(await rbac.can(support, 'people.view')).toBe(true);
    await rbac.revoke(held.id, owner);
    // Group membership carries a built-in role, and stops carrying it when removed.
    const group = await control.staffGroup.create({
      data: { name: `night-${suffix}`, createdBy: owner },
    });
    const viaGroup = await rbac.grant({
      roleId: await roleId('billing'),
      principalType: 'GROUP',
      principalId: group.id,
      kind: 'ACTIVE',
      grantedBy: owner,
    });
    await rbac.addGroupMember(group.id, support, owner);
    expect(await rbac.can(support, 'tags.write')).toBe(true);
    await rbac.removeGroupMember(group.id, support, owner);
    expect(await rbac.can(support, 'tags.write')).toBe(false);
    await rbac.revoke(viaGroup.id, owner);
  });

  it('the reconciler restores a deleted tuple and removes a stray one', async () => {
    const ownerRole = await roleId('owner');
    await fga.write({ deletes: [assigneeTuple(ownerRole, 'STAFF', owner)] });
    await fga.write({ writes: [assigneeTuple(ownerRole, 'STAFF', support)] });
    expect(await rbac.can(owner, 'restrict.ban')).toBe(false);
    expect(await rbac.reconcile({ dryRun: true })).toMatchObject({ fixed: 2 });
    expect(await rbac.reconcile({ dryRun: false })).toMatchObject({ fixed: 2 });
    expect(await rbac.can(owner, 'restrict.ban')).toBe(true);
    expect(await rbac.can(support, 'restrict.ban')).toBe(false);
    expect(await rbac.reconcile({ dryRun: false })).toMatchObject({ fixed: 0 });
  });

  describe('security review fixes (4 Nov)', () => {
    /** An OpenFGA client whose next write fails, then works again. */
    const failNextWrite = () => {
      const original = fga.write.bind(fga);
      const spy = vi
        .spyOn(fga, 'write')
        .mockImplementationOnce(() => Promise.reject(new Error('fga down')));
      return () => {
        spy.mockRestore();
        void original;
      };
    };

    it('revoking Owner eligibility ends an open elevation at once, and reconcile keeps it ended', async () => {
      const ownerRole = await roleId('owner');
      const eligible = await rbac.grant({
        roleId: ownerRole,
        principalType: 'STAFF',
        principalId: support,
        kind: 'ELIGIBLE',
        grantedBy: owner,
      });
      const elevation = await rbac.startElevation({
        staffId: support,
        assignmentId: eligible.id,
        reason: 'urgent abuse case',
        expiresAt: new Date(Date.now() + 3_600_000),
      });
      expect(await rbac.can(support, 'restrict.ban')).toBe(true);
      await rbac.revoke(eligible.id, owner);
      expect(await rbac.can(support, 'restrict.ban')).toBe(false);
      const row = await control.staffElevation.findUniqueOrThrow({
        where: { id: elevation.id },
      });
      expect(row.endedAt).not.toBeNull();
      expect(row.endedBy).toBe(owner);
      await rbac.reconcile({ dryRun: false });
      expect(await rbac.can(support, 'restrict.ban')).toBe(false);
    });

    it('reconcile ignores an open elevation whose eligibility was revoked behind its back', async () => {
      const ownerRole = await roleId('owner');
      const eligible = await rbac.grant({
        roleId: ownerRole,
        principalType: 'STAFF',
        principalId: support,
        kind: 'ELIGIBLE',
        grantedBy: owner,
      });
      await rbac.startElevation({
        staffId: support,
        assignmentId: eligible.id,
        reason: 'urgent abuse case',
        expiresAt: new Date(Date.now() + 3_600_000),
      });
      // Someone revokes the row directly in the database (or an older binary did).
      await control.staffRoleAssignment.update({
        where: { id: eligible.id },
        data: { revokedAt: new Date(), revokedBy: 'db' },
      });
      await rbac.reconcile({ dryRun: false });
      expect(await rbac.can(support, 'restrict.ban')).toBe(false);
      await control.staffElevation.updateMany({
        where: { staffId: support, endedAt: null },
        data: { endedAt: new Date() },
      });
    });

    it('a failed OpenFGA write on grant leaves the assignment revoked in Postgres and no tuple', async () => {
      const restore = failNextWrite();
      try {
        await expect(
          rbac.grant({
            roleId: await roleId('billing'),
            principalType: 'STAFF',
            principalId: support,
            kind: 'ACTIVE',
            grantedBy: owner,
          }),
        ).rejects.toThrow('fga down');
      } finally {
        restore();
      }
      const rows = await control.staffRoleAssignment.findMany({
        where: { principalId: support, roleId: await roleId('billing') },
      });
      expect(rows.every((r) => r.revokedAt !== null)).toBe(true);
      expect(await rbac.can(support, 'tags.write')).toBe(false);
      expect(await rbac.reconcile({ dryRun: true })).toMatchObject({
        fixed: 0,
      });
    });

    it('a failed OpenFGA write on group add leaves no member row', async () => {
      const group = await control.staffGroup.create({
        data: { name: `g-fail-${suffix}`, createdBy: owner },
      });
      const restore = failNextWrite();
      try {
        await expect(
          rbac.addGroupMember(group.id, support, owner),
        ).rejects.toThrow('fga down');
      } finally {
        restore();
      }
      expect(
        await control.staffGroupMember.count({ where: { groupId: group.id } }),
      ).toBe(0);
    });

    it('a failed OpenFGA delete on revoke keeps the assignment active (nothing half done)', async () => {
      const a = await rbac.grant({
        roleId: await roleId('dev'),
        principalType: 'STAFF',
        principalId: support,
        kind: 'ACTIVE',
        grantedBy: owner,
      });
      const restore = failNextWrite();
      try {
        await expect(rbac.revoke(a.id, owner)).rejects.toThrow('fga down');
      } finally {
        restore();
      }
      expect(
        (
          await control.staffRoleAssignment.findUniqueOrThrow({
            where: { id: a.id },
          })
        ).revokedAt,
      ).toBeNull();
      await rbac.revoke(a.id, owner);
      expect(await rbac.can(support, 'errors.view')).toBe(false);
    });

    it('concurrent edits of one custom role leave OpenFGA on the newest version', async () => {
      const role = await rbac.saveCustomRole({
        key: `race-${suffix}`,
        name: 'Race',
        permissions: ['people.view'],
        by: owner,
      });
      const held = await rbac.grant({
        roleId: role.id,
        principalType: 'STAFF',
        principalId: support,
        kind: 'ACTIVE',
        grantedBy: owner,
      });
      onTestFinished(() => rbac.revoke(held.id, owner));
      const sets: string[][] = [
        ['people.view', 'notes.write'],
        ['people.view', 'tags.write'],
        ['orgs.view'],
        ['people.search', 'errors.view'],
      ];
      await Promise.all(
        sets.map((permissions) =>
          rbac.saveCustomRole({
            roleId: role.id,
            key: role.key,
            name: 'Race',
            permissions,
            by: owner,
          }),
        ),
      );
      const saved = await control.staffRole.findUniqueOrThrow({
        where: { id: role.id },
        include: { versions: true },
      });
      const newest = saved.versions.find(
        (v) => v.version === saved.currentVersion,
      )!.permissions;
      for (const p of [
        'people.view',
        'notes.write',
        'tags.write',
        'orgs.view',
        'people.search',
        'errors.view',
      ] as const)
        expect(await rbac.can(support, p)).toBe(newest.includes(p));
    });
  });

  describe('expiry boundaries (security review, 4 Nov)', () => {
    it('refuses an elevation on an expired eligibility and an end time already past', async () => {
      const ownerRole = await roleId('owner');
      const eligible = await rbac.grant({
        roleId: ownerRole,
        principalType: 'STAFF',
        principalId: support,
        kind: 'ELIGIBLE',
        expiresAt: new Date(Date.now() + 800),
        grantedBy: owner,
      });
      await expect(
        rbac.startElevation({
          staffId: support,
          assignmentId: eligible.id,
          reason: 'urgent abuse case',
          expiresAt: new Date(Date.now() - 1),
        }),
      ).rejects.toMatchObject({ response: { code: 'already_expired' } });
      await new Promise((r) => setTimeout(r, 900));
      await expect(
        rbac.startElevation({
          staffId: support,
          assignmentId: eligible.id,
          reason: 'urgent abuse case',
          expiresAt: new Date(Date.now() + 60_000),
        }),
      ).rejects.toMatchObject({ response: { code: 'not_eligible' } });
      await rbac.revoke(eligible.id, owner);
    });

    it('clamps an elevation to the eligibility expiry and to one hour', async () => {
      const ownerRole = await roleId('owner');
      const soon = new Date(Date.now() + 1500);
      const eligible = await rbac.grant({
        roleId: ownerRole,
        principalType: 'STAFF',
        principalId: support,
        kind: 'ELIGIBLE',
        expiresAt: soon,
        grantedBy: owner,
      });
      const e = await rbac.startElevation({
        staffId: support,
        assignmentId: eligible.id,
        reason: 'urgent abuse case',
        expiresAt: new Date(Date.now() + 10 * 3_600_000),
      });
      expect(e.expiresAt.getTime()).toBe(soon.getTime());
      expect(await rbac.can(support, 'restrict.ban')).toBe(true);
      await new Promise((r) => setTimeout(r, 1700));
      expect(await rbac.can(support, 'restrict.ban')).toBe(false);
      await rbac.reconcile({ dryRun: false });
      expect(await rbac.can(support, 'restrict.ban')).toBe(false);
      await rbac.revoke(eligible.id, owner);

      const forever = await rbac.grant({
        roleId: ownerRole,
        principalType: 'STAFF',
        principalId: support,
        kind: 'ELIGIBLE',
        grantedBy: owner,
      });
      const long = await rbac.startElevation({
        staffId: support,
        assignmentId: forever.id,
        reason: 'urgent abuse case',
        expiresAt: new Date(Date.now() + 10 * 3_600_000),
      });
      expect(
        long.expiresAt.getTime() - long.startedAt.getTime(),
      ).toBeLessThanOrEqual(3_600_000 + 1000);
      await rbac.revoke(forever.id, owner);
      expect(await rbac.can(support, 'restrict.ban')).toBe(false);
    });

    it('reconcile does not project an elevation that runs past its eligibility', async () => {
      const ownerRole = await roleId('owner');
      const eligible = await rbac.grant({
        roleId: ownerRole,
        principalType: 'STAFF',
        principalId: support,
        kind: 'ELIGIBLE',
        grantedBy: owner,
      });
      const e = await rbac.startElevation({
        staffId: support,
        assignmentId: eligible.id,
        reason: 'urgent abuse case',
        expiresAt: new Date(Date.now() + 3_600_000),
      });
      // The eligibility is shortened behind the elevation's back (a direct database edit).
      await control.staffRoleAssignment.update({
        where: { id: eligible.id },
        data: { expiresAt: new Date(Date.now() + 60_000) },
      });
      await rbac.reconcile({ dryRun: false });
      expect(await rbac.can(support, 'restrict.ban')).toBe(false);
      await control.staffElevation.update({
        where: { id: e.id },
        data: { endedAt: new Date() },
      });
      await rbac.revoke(eligible.id, owner);
    });
  });

  describe('concurrency, 50 rounds each (security review, 4 Nov)', () => {
    it('grant racing revoke never leaves power behind a revoked row', async () => {
      const devRole = await roleId('dev');
      for (let i = 0; i < 50; i++) {
        const grant = rbac.grant({
          roleId: devRole,
          principalType: 'STAFF',
          principalId: support,
          kind: 'ACTIVE',
          grantedBy: owner,
        });
        // Revoke as soon as the row is committed, racing the grant's projection.
        const revoke = (async () => {
          for (let tries = 0; tries < 200; tries++) {
            const row = await control.staffRoleAssignment.findFirst({
              where: { roleId: devRole, principalId: support, revokedAt: null },
            });
            if (row) return rbac.revoke(row.id, owner);
          }
          return rbac.revoke((await grant).id, owner);
        })();
        await Promise.allSettled([grant, revoke]);
        const live = await control.staffRoleAssignment.count({
          where: { roleId: devRole, principalId: support, revokedAt: null },
        });
        expect(live).toBe(0);
        expect(await rbac.can(support, 'errors.view')).toBe(false);
      }
    }, 120_000);

    it('elevation racing an eligibility revoke never leaves power behind', async () => {
      const ownerRole = await roleId('owner');
      for (let i = 0; i < 50; i++) {
        const eligible = await rbac.grant({
          roleId: ownerRole,
          principalType: 'STAFF',
          principalId: support,
          kind: 'ELIGIBLE',
          grantedBy: owner,
        });
        await Promise.allSettled([
          rbac.startElevation({
            staffId: support,
            assignmentId: eligible.id,
            reason: 'urgent abuse case',
            expiresAt: new Date(Date.now() + 60_000),
          }),
          rbac.revoke(eligible.id, owner),
        ]);
        expect(await rbac.can(support, 'restrict.ban')).toBe(false);
        const open = await control.staffElevation.count({
          where: { staffId: support, endedAt: null },
        });
        expect(open).toBe(0);
      }
    }, 120_000);

    it('two edits of one role always leave OpenFGA on the committed version', async () => {
      const role = await rbac.saveCustomRole({
        key: `edit-${suffix}`,
        name: 'Edit',
        permissions: ['people.view'],
        by: owner,
      });
      const held = await rbac.grant({
        roleId: role.id,
        principalType: 'STAFF',
        principalId: support,
        kind: 'ACTIVE',
        grantedBy: owner,
      });
      onTestFinished(() => rbac.revoke(held.id, owner));
      const all = [
        'people.view',
        'notes.write',
        'tags.write',
        'orgs.view',
      ] as const;
      for (let i = 0; i < 50; i++) {
        await Promise.all([
          rbac.saveCustomRole({
            roleId: role.id,
            key: role.key,
            name: 'Edit',
            permissions: ['people.view', all[(i % 3) + 1]!],
            by: owner,
          }),
          rbac.saveCustomRole({
            roleId: role.id,
            key: role.key,
            name: 'Edit',
            permissions: [all[((i + 1) % 3) + 1]!],
            by: owner,
          }),
        ]);
        const saved = await control.staffRole.findUniqueOrThrow({
          where: { id: role.id },
          include: { versions: true },
        });
        const newest = saved.versions.find(
          (v) => v.version === saved.currentVersion,
        )!.permissions;
        for (const p of all)
          expect(await rbac.can(support, p)).toBe(newest.includes(p));
      }
    }, 180_000);
  });

  describe('reconciler full sweep (security review, 4 Nov)', () => {
    it('removes a rogue assignee tuple written straight into OpenFGA', async () => {
      const rogue = randomUUID();
      await fga.write({
        writes: [
          {
            user: `staff:${rogue}`,
            relation: 'assignee',
            object: `role:${await roleId('owner')}~platform~manar`,
          },
        ],
      });
      expect(await rbac.can(rogue, 'restrict.ban')).toBe(true);
      const plan = await rbac.reconcile({ dryRun: true });
      expect(plan.wouldDelete).toBeGreaterThanOrEqual(1);
      expect(await rbac.can(rogue, 'restrict.ban')).toBe(true); // dry run changed nothing
      await rbac.reconcile({ dryRun: false });
      expect(await rbac.can(rogue, 'restrict.ban')).toBe(false);
    });

    it('removes every tuple of a role Postgres does not know', async () => {
      const orphan = randomUUID();
      const someone = randomUUID();
      await fga.write({
        writes: [
          {
            user: `role:${orphan}~platform~manar#assignee`,
            relation: 'restrict_ban',
            object: 'platform:manar',
          },
          {
            user: `staff:${someone}`,
            relation: 'assignee',
            object: `role:${orphan}~platform~manar`,
          },
        ],
      });
      expect(await rbac.can(someone, 'restrict.ban')).toBe(true);
      await rbac.reconcile({ dryRun: false });
      expect(await rbac.can(someone, 'restrict.ban')).toBe(false);
      expect(await fga.readObject(`role:${orphan}~platform~manar`)).toEqual([]);
    });

    it('removes a user shape the staff model never writes (a nested group)', async () => {
      const group = await control.staffGroup.create({
        data: { name: `sweep-${suffix}`, createdBy: owner },
      });
      const smuggled = randomUUID();
      await fga.write({
        writes: [
          {
            user: `group:${smuggled}#member`,
            relation: 'member',
            object: `group:${group.id}`,
          },
        ],
      });
      await rbac.reconcile({ dryRun: false });
      expect(await fga.readObject(`group:${group.id}`)).toEqual([]);
    });

    it('refuses a mass delete without the explicit flag and records it', async () => {
      const ownerRole = await roleId('owner');
      const rogues = Array.from(
        { length: StaffRbacService.MAX_RECONCILE_DELETES + 1 },
        () => randomUUID(),
      );
      await fga.write({
        writes: rogues.map((r) => ({
          user: `staff:${r}`,
          relation: 'assignee',
          object: `role:${ownerRole}~platform~manar`,
        })),
      });
      const blocked = await rbac.reconcile({ dryRun: false });
      expect(blocked).toMatchObject({ blocked: true, fixed: 0 });
      expect(blocked.wouldDelete).toBeGreaterThan(
        StaffRbacService.MAX_RECONCILE_DELETES,
      );
      expect(await rbac.can(rogues[0]!, 'restrict.ban')).toBe(true);
      const event = await control.staffAuditEvent.findFirst({
        where: { action: 'rbac.reconcile_blocked' },
        orderBy: { seq: 'desc' },
      });
      expect(event).not.toBeNull();
      const done = await rbac.reconcile({
        dryRun: false,
        allowMassDelete: true,
      });
      expect(done.blocked).toBeFalsy();
      expect(await rbac.can(rogues[0]!, 'restrict.ban')).toBe(false);
    });
  });

  it('groups cannot hold Owner or a custom role (security review, 4 Nov)', async () => {
    const group = await control.staffGroup.create({
      data: { name: `priv-${suffix}`, createdBy: owner },
    });
    await expect(
      rbac.grant({
        roleId: await roleId('owner'),
        principalType: 'GROUP',
        principalId: group.id,
        kind: 'ACTIVE',
        grantedBy: owner,
      }),
    ).rejects.toMatchObject({ response: { code: 'group_cannot_hold_role' } });
    const custom = await rbac.saveCustomRole({
      key: `gc-${suffix}`,
      name: 'GC',
      permissions: ['people.view'],
      by: owner,
    });
    await expect(
      rbac.grant({
        roleId: custom.id,
        principalType: 'GROUP',
        principalId: group.id,
        kind: 'ACTIVE',
        grantedBy: owner,
      }),
    ).rejects.toMatchObject({ response: { code: 'group_cannot_hold_role' } });
    const ok = await rbac.grant({
      roleId: await roleId('support'),
      principalType: 'GROUP',
      principalId: group.id,
      kind: 'ACTIVE',
      grantedBy: owner,
    });
    await rbac.revoke(ok.id, owner);
  });
});
