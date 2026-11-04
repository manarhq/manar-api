import {
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { Counter } from 'prom-client';
import {
  OpenFgaClientService,
  type TupleKey,
} from '../../authorization/openfga-client.service';
import { ControlPrismaService } from '../../database/control-prisma.service';
import type {
  StaffRole,
  StaffRoleAssignment,
} from '../../generated/control-client/client';
import { StaffAuditService } from '../audit/staff-audit.service';
import {
  BUILT_IN_ROLE_KEYS,
  BUILT_IN_ROLE_NAMES,
  BUILT_IN_ROLES,
  OWNER_ONLY,
  PLATFORM_OBJECT,
  STAFF_PERMISSIONS,
  fgaRelation,
  isStaffPermission,
  roleObject,
  type StaffPermission,
} from './permissions';

export const WITHIN_WINDOW = 'within_window';

const reconcileFixed = new Counter({
  name: 'rbac_reconcile_fixed_total',
  help: 'OpenFGA staff tuples the reconciler had to repair towards Postgres',
});

export interface GrantInput {
  roleId: string;
  principalType: 'STAFF' | 'GROUP';
  principalId: string;
  kind: 'ACTIVE' | 'ELIGIBLE';
  expiresAt?: Date;
  grantedBy: string;
  changeRequestId?: string;
}

const principalUser = (type: 'STAFF' | 'GROUP', id: string) =>
  type === 'STAFF' ? `staff:${id}` : `group:${id}#member`;

/** The `role#assignee` tuple an ACTIVE assignment (or an elevation) projects to. */
export function assigneeTuple(
  roleId: string,
  principalType: 'STAFF' | 'GROUP',
  principalId: string,
  expiresAt?: Date | null,
): TupleKey {
  return {
    user: principalUser(principalType, principalId),
    relation: 'assignee',
    object: roleObject(roleId),
    ...(expiresAt
      ? {
          condition: {
            name: WITHIN_WINDOW,
            context: { expires_at: expiresAt.toISOString() },
          },
        }
      : {}),
  };
}

const permissionTuple = (roleId: string, p: StaffPermission): TupleKey => ({
  user: `${roleObject(roleId)}#assignee`,
  relation: fgaRelation(p),
  object: PLATFORM_OBJECT,
});

const tupleKey = (t: TupleKey) => {
  const expires = t.condition?.context?.expires_at;
  // OpenFGA reads a timestamp back in its own format; compare instants, not strings.
  const at = typeof expires === 'string' ? new Date(expires).getTime() : '';
  return `${t.user}|${t.relation}|${t.object}|${at}`;
};

/**
 * Staff RBAC (DESK spec §10.1 to §10.3). Postgres is the source of truth; OpenFGA holds the
 * projection every check reads. AC-29: grants write Postgres then OpenFGA inside one transaction
 * (an OpenFGA failure rolls the row back); revocations delete the tuple first. AC-30: no cache.
 */
@Injectable()
export class StaffRbacService {
  private readonly logger = new Logger(StaffRbacService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly fga: OpenFgaClientService,
    private readonly audit: StaffAuditService,
  ) {}

  /** Throws when OpenFGA cannot answer: callers turn that into 503, never into an allow. */
  can(staffId: string, p: StaffPermission): Promise<boolean> {
    return this.fga.check(
      {
        user: `staff:${staffId}`,
        relation: fgaRelation(p),
        object: PLATFORM_OBJECT,
      },
      {
        consistency: 'high',
        context: { current_time: new Date().toISOString() },
      },
    );
  }

  async permissionsOf(staffId: string): Promise<StaffPermission[]> {
    const answers = await Promise.all(
      STAFF_PERMISSIONS.map((p) => this.can(staffId, p)),
    );
    return STAFF_PERMISSIONS.filter((_, i) => answers[i]);
  }

  /** Idempotent: built-in roles exist at the permissions this code defines, tuples included. */
  async ensureBuiltInRoles(): Promise<void> {
    for (const key of BUILT_IN_ROLE_KEYS) {
      const wanted = [...BUILT_IN_ROLES[key]].sort();
      let role = await this.control.staffRole.findUnique({
        where: { key },
        include: { versions: { orderBy: { version: 'desc' }, take: 1 } },
      });
      if (!role) {
        await this.control.staffRole.create({
          data: {
            key,
            name: BUILT_IN_ROLE_NAMES[key],
            builtIn: true,
            versions: {
              create: { version: 1, permissions: wanted, createdBy: 'system' },
            },
          },
        });
        role = await this.control.staffRole.findUniqueOrThrow({
          where: { key },
          include: { versions: { orderBy: { version: 'desc' }, take: 1 } },
        });
      } else if (
        JSON.stringify([...(role.versions[0]?.permissions ?? [])].sort()) !==
        JSON.stringify(wanted)
      ) {
        const version = role.currentVersion + 1;
        await this.control.$transaction([
          this.control.staffRoleVersion.create({
            data: {
              roleId: role.id,
              version,
              permissions: wanted,
              createdBy: 'system',
            },
          }),
          this.control.staffRole.update({
            where: { id: role.id },
            data: { currentVersion: version },
          }),
        ]);
      }
      await this.syncRolePermissions(role.id, wanted);
    }
  }

  async grant(input: GrantInput): Promise<StaffRoleAssignment> {
    const role = await this.control.staffRole.findUnique({
      where: { id: input.roleId },
    });
    if (!role || role.archivedAt) throw new NotFoundException('Unknown role');
    return this.control.$transaction(async (tx) => {
      const existing = await tx.staffRoleAssignment.findFirst({
        where: {
          roleId: input.roleId,
          principalType: input.principalType,
          principalId: input.principalId,
          kind: input.kind,
          revokedAt: null,
        },
      });
      if (existing)
        throw new ConflictException({
          code: 'already_assigned',
          message: 'This role is already assigned.',
        });
      const row = await tx.staffRoleAssignment.create({
        data: {
          roleId: input.roleId,
          principalType: input.principalType,
          principalId: input.principalId,
          kind: input.kind,
          expiresAt: input.expiresAt,
          grantedBy: input.grantedBy,
          changeRequestId: input.changeRequestId,
        },
      });
      await this.audit.append(
        {
          staffId: input.grantedBy === 'system' ? null : input.grantedBy,
          action: 'staff.role_granted',
          targetType: input.principalType === 'STAFF' ? 'STAFF' : 'GROUP',
          targetId: input.principalId,
          data: {
            roleKey: role.key,
            kind: input.kind,
            expiresAt: input.expiresAt?.toISOString() ?? null,
            changeRequestId: input.changeRequestId ?? null,
          },
        },
        tx,
      );
      // ELIGIBLE grants no power until an elevation; only ACTIVE projects to a tuple.
      if (input.kind === 'ACTIVE')
        await this.fga.write({
          writes: [
            assigneeTuple(
              input.roleId,
              input.principalType,
              input.principalId,
              input.expiresAt,
            ),
          ],
        });
      return row;
    });
  }

  async revoke(assignmentId: string, by: string): Promise<void> {
    const a = await this.control.staffRoleAssignment.findUnique({
      where: { id: assignmentId },
    });
    if (!a || a.revokedAt) throw new NotFoundException('Unknown assignment');
    if (a.kind === 'ACTIVE')
      await this.fga.write({
        deletes: [
          assigneeTuple(a.roleId, a.principalType, a.principalId, a.expiresAt),
        ],
        ignoreMissingDeletes: true,
      });
    await this.control.$transaction(async (tx) => {
      await tx.staffRoleAssignment.update({
        where: { id: a.id },
        data: { revokedAt: new Date(), revokedBy: by },
      });
      await this.audit.append(
        {
          staffId: by,
          action: 'staff.role_revoked',
          targetType: a.principalType === 'STAFF' ? 'STAFF' : 'GROUP',
          targetId: a.principalId,
          data: { assignmentId: a.id, roleId: a.roleId },
        },
        tx,
      );
    });
  }

  /**
   * Creates a custom role or a new version of one. AC-31: no Owner-only permission, and the editor
   * cannot hand out a permission they do not hold themselves.
   */
  async saveCustomRole(input: {
    roleId?: string;
    key: string;
    name: string;
    description?: string;
    permissions: string[];
    by: string;
  }): Promise<StaffRole> {
    const perms = [...new Set(input.permissions)].sort();
    for (const p of perms) {
      if (!isStaffPermission(p))
        throw new ForbiddenException({
          code: 'unknown_permission',
          message: `Unknown permission ${p}.`,
        });
      if (OWNER_ONLY.has(p))
        throw new ForbiddenException({
          code: 'owner_only_permission',
          message: 'Owner-only permissions cannot go into a custom role.',
        });
    }
    const held = new Set(await this.permissionsOf(input.by));
    const unheld = perms.filter((p) => !held.has(p as StaffPermission));
    if (unheld.length)
      throw new ForbiddenException({
        code: 'cannot_grant_unheld',
        message: 'You can only grant permissions you hold yourself.',
        permissions: unheld,
      });

    const role = await this.control.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext('staff_roles'))`;
      let saved: StaffRole;
      if (input.roleId) {
        const current = await tx.staffRole.findUnique({
          where: { id: input.roleId },
        });
        if (!current || current.builtIn || current.archivedAt)
          throw new ForbiddenException({
            code: 'role_not_editable',
            message: 'Built-in roles cannot be edited.',
          });
        const version = current.currentVersion + 1;
        await tx.staffRoleVersion.create({
          data: {
            roleId: current.id,
            version,
            permissions: perms,
            createdBy: input.by,
          },
        });
        saved = await tx.staffRole.update({
          where: { id: current.id },
          data: {
            currentVersion: version,
            name: input.name,
            description: input.description ?? current.description,
          },
        });
      } else {
        if (
          (BUILT_IN_ROLE_KEYS as readonly string[]).includes(input.key) ||
          !/^[a-z][a-z0-9_-]{1,40}$/.test(input.key)
        )
          throw new ForbiddenException({
            code: 'bad_role_key',
            message: 'Choose another role key.',
          });
        saved = await tx.staffRole.create({
          data: {
            key: input.key,
            name: input.name,
            description: input.description ?? '',
            versions: {
              create: { version: 1, permissions: perms, createdBy: input.by },
            },
          },
        });
      }
      await this.audit.append(
        {
          staffId: input.by,
          action: 'staff.role_saved',
          targetType: 'ROLE',
          targetId: saved.id,
          data: {
            key: saved.key,
            version: saved.currentVersion,
            permissions: perms,
          },
        },
        tx,
      );
      return saved;
    });
    await this.syncRolePermissions(role.id, perms as StaffPermission[]);
    return role;
  }

  async addGroupMember(groupId: string, staffId: string, by: string) {
    await this.control.$transaction(async (tx) => {
      await tx.staffGroupMember.create({
        data: { groupId, staffId, addedBy: by },
      });
      await this.audit.append(
        {
          staffId: by,
          action: 'staff.group_member_added',
          targetType: 'GROUP',
          targetId: groupId,
          data: { staffId },
        },
        tx,
      );
      await this.fga.write({
        writes: [
          {
            user: `staff:${staffId}`,
            relation: 'member',
            object: `group:${groupId}`,
          },
        ],
      });
    });
  }

  async removeGroupMember(groupId: string, staffId: string, by: string) {
    await this.fga.write({
      deletes: [
        {
          user: `staff:${staffId}`,
          relation: 'member',
          object: `group:${groupId}`,
        },
      ],
      ignoreMissingDeletes: true,
    });
    await this.control.$transaction(async (tx) => {
      await tx.staffGroupMember.delete({
        where: { groupId_staffId: { groupId, staffId } },
      });
      await this.audit.append(
        {
          staffId: by,
          action: 'staff.group_member_removed',
          targetType: 'GROUP',
          targetId: groupId,
          data: { staffId },
        },
        tx,
      );
    });
  }

  /** Makes the role's permission tuples exactly `perms`: adds the new, removes the dropped. */
  private async syncRolePermissions(
    roleId: string,
    perms: StaffPermission[],
  ): Promise<void> {
    const actual = (await this.fga.readObject(PLATFORM_OBJECT)).filter(
      (t) => t.user === `${roleObject(roleId)}#assignee`,
    );
    const wanted = perms.map((p) => permissionTuple(roleId, p));
    const have = new Set(actual.map(tupleKey));
    const want = new Set(wanted.map(tupleKey));
    await this.fga.write({
      writes: wanted.filter((t) => !have.has(tupleKey(t))),
      deletes: actual.filter((t) => !want.has(tupleKey(t))),
      ignoreMissingDeletes: true,
    });
  }

  /**
   * AC-29 reconciler: rebuilds the desired tuples from Postgres and repairs OpenFGA towards them.
   * Reads only the staff objects (platform:manar, each role instance, each group).
   */
  async reconcile(opts: { dryRun: boolean }): Promise<{ fixed: number }> {
    const now = new Date();
    const [roles, assignments, members, elevations, groups] = await Promise.all(
      [
        this.control.staffRole.findMany({ include: { versions: true } }),
        this.control.staffRoleAssignment.findMany({
          where: {
            kind: 'ACTIVE',
            revokedAt: null,
            OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
          },
        }),
        this.control.staffGroupMember.findMany(),
        this.control.staffElevation.findMany({
          where: { endedAt: null, expiresAt: { gt: now } },
        }),
        this.control.staffGroup.findMany({ select: { id: true } }),
      ],
    );
    const desired: TupleKey[] = [];
    for (const r of roles) {
      if (r.archivedAt) continue;
      const v = r.versions.find((x) => x.version === r.currentVersion);
      for (const p of v?.permissions ?? [])
        if (isStaffPermission(p)) desired.push(permissionTuple(r.id, p));
    }
    for (const a of assignments)
      desired.push(
        assigneeTuple(a.roleId, a.principalType, a.principalId, a.expiresAt),
      );
    for (const e of elevations)
      desired.push(assigneeTuple(e.roleId, 'STAFF', e.staffId, e.expiresAt));
    for (const m of members)
      desired.push({
        user: `staff:${m.staffId}`,
        relation: 'member',
        object: `group:${m.groupId}`,
      });

    const objects = [
      PLATFORM_OBJECT,
      ...roles.map((r) => roleObject(r.id)),
      ...groups.map((g) => `group:${g.id}`),
    ];
    const actual = (
      await Promise.all(objects.map((o) => this.fga.readObject(o)))
    ).flat();
    const want = new Set(desired.map(tupleKey));
    const have = new Set(actual.map(tupleKey));
    const writes = desired.filter((t) => !have.has(tupleKey(t)));
    // Only staff-shaped tuples on these objects are ours to delete.
    const deletes = actual.filter((t) => !want.has(tupleKey(t)));
    const fixed = writes.length + deletes.length;
    if (fixed && !opts.dryRun) {
      await this.fga.write({ writes, deletes, ignoreMissingDeletes: true });
      reconcileFixed.inc(fixed);
      this.logger.warn(`RBAC reconcile repaired ${fixed} staff tuple(s)`);
    }
    return { fixed };
  }
}
