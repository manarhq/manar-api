import 'dotenv/config';
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

  it('an OpenFGA failure on grant leaves no Postgres row (fail closed)', async () => {
    const broken = new OpenFgaClientService(config);
    const brokenRbac = new StaffRbacService(control, broken, audit); // never initialised: every call throws
    const before = await control.staffRoleAssignment.count({
      where: { principalId: support },
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
        where: { principalId: support },
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

  it('a new version of a custom role removes a dropped permission from every holder', async () => {
    const role = await rbac.saveCustomRole({
      key: `lead2-${suffix}`,
      name: 'Lead',
      permissions: ['people.view', 'notes.write'],
      by: owner,
    });
    const group = await control.staffGroup.create({
      data: { name: `night-${suffix}`, createdBy: owner },
    });
    await rbac.addGroupMember(group.id, support, owner);
    await rbac.grant({
      roleId: role.id,
      principalType: 'GROUP',
      principalId: group.id,
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
    await rbac.removeGroupMember(group.id, support, owner);
    expect(await rbac.can(support, 'people.view')).toBe(false);
  });

  it('the reconciler restores a deleted tuple and removes a stray one', async () => {
    const ownerRole = await roleId('owner');
    await fga.write({ deletes: [assigneeTuple(ownerRole, 'STAFF', owner)] });
    await fga.write({ writes: [assigneeTuple(ownerRole, 'STAFF', support)] });
    expect(await rbac.can(owner, 'restrict.ban')).toBe(false);
    expect(await rbac.reconcile({ dryRun: true })).toEqual({ fixed: 2 });
    expect(await rbac.reconcile({ dryRun: false })).toEqual({ fixed: 2 });
    expect(await rbac.can(owner, 'restrict.ban')).toBe(true);
    expect(await rbac.can(support, 'restrict.ban')).toBe(false);
    expect(await rbac.reconcile({ dryRun: false })).toEqual({ fixed: 0 });
  });
});
