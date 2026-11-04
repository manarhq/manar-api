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
/** `revokedBy` / `endedBy` when the OpenFGA projection of a grant failed and it was rolled back. */
export const PROJECTION_FAILED = 'system:projection_failed';

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
      await this.withRoleLock(async () => {
        const role = await this.control.staffRole.findUnique({
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
                create: {
                  version: 1,
                  permissions: wanted,
                  createdBy: 'system',
                },
              },
            },
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
        const saved = await this.control.staffRole.findUniqueOrThrow({
          where: { key },
        });
        await this.syncRolePermissions(saved.id);
      });
    }
  }

  /**
   * AC-29: the Postgres row and its audit row commit first, then the tuple is written. If the
   * tuple write fails, the row is revoked as a compensation (history kept) and the error is
   * rethrown, so Postgres never says "granted" for a grant the caller saw fail. A crash between
   * the two leaves Postgres granted and audited; the reconciler projects it.
   */
  async grant(input: GrantInput): Promise<StaffRoleAssignment> {
    const role = await this.control.staffRole.findUnique({
      where: { id: input.roleId },
    });
    if (!role || role.archivedAt) throw new NotFoundException('Unknown role');
    const row = await this.control.$transaction(async (tx) => {
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
      const created = await tx.staffRoleAssignment.create({
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
            assignmentId: created.id,
            roleKey: role.key,
            kind: input.kind,
            expiresAt: input.expiresAt?.toISOString() ?? null,
            changeRequestId: input.changeRequestId ?? null,
          },
        },
        tx,
      );
      return created;
    });
    // ELIGIBLE grants no power until an elevation; only ACTIVE projects to a tuple.
    if (input.kind === 'ACTIVE') {
      try {
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
      } catch (error) {
        await this.compensateGrant(row.id);
        throw error;
      }
    }
    return row;
  }

  private async compensateGrant(assignmentId: string): Promise<void> {
    await this.control.$transaction(async (tx) => {
      await tx.staffRoleAssignment.update({
        where: { id: assignmentId },
        data: { revokedAt: new Date(), revokedBy: PROJECTION_FAILED },
      });
      await this.audit.append(
        {
          staffId: null,
          action: 'staff.role_grant_rolled_back',
          data: { assignmentId, reason: 'openfga_write_failed' },
        },
        tx,
      );
    });
  }

  /**
   * AC-29: tuples are deleted first, then Postgres is updated, so a failure part-way never leaves
   * power behind. Revoking an ELIGIBLE assignment also ends every open elevation that rests on it.
   */
  async revoke(assignmentId: string, by: string): Promise<void> {
    const a = await this.control.staffRoleAssignment.findUnique({
      where: { id: assignmentId },
    });
    if (!a || a.revokedAt) throw new NotFoundException('Unknown assignment');
    const elevations =
      a.kind === 'ELIGIBLE'
        ? await this.control.staffElevation.findMany({
            where: { assignmentId: a.id, endedAt: null },
          })
        : [];
    const deletes = [
      ...(a.kind === 'ACTIVE'
        ? [assigneeTuple(a.roleId, a.principalType, a.principalId, a.expiresAt)]
        : []),
      ...elevations.map((e) =>
        assigneeTuple(e.roleId, 'STAFF', e.staffId, e.expiresAt),
      ),
    ];
    if (deletes.length)
      await this.fga.write({ deletes, ignoreMissingDeletes: true });
    await this.control.$transaction(async (tx) => {
      const now = new Date();
      await tx.staffElevation.updateMany({
        where: { assignmentId: a.id, endedAt: null },
        data: { endedAt: now, endedBy: by },
      });
      await tx.staffRoleAssignment.update({
        where: { id: a.id },
        data: { revokedAt: now, revokedBy: by },
      });
      await this.audit.append(
        {
          staffId: by,
          action: 'staff.role_revoked',
          targetType: a.principalType === 'STAFF' ? 'STAFF' : 'GROUP',
          targetId: a.principalId,
          data: {
            assignmentId: a.id,
            roleId: a.roleId,
            elevationsEnded: elevations.map((e) => e.id),
          },
        },
        tx,
      );
    });
  }

  /**
   * Turns an ELIGIBLE assignment on for the caller until `expiresAt` (spec §11.1). The row commits
   * first, then the conditional tuple; a failed write ends the row again. Expired rows still open
   * are closed (and their tuples removed) first, so the one-open-elevation index admits the new one.
   */
  async startElevation(input: {
    staffId: string;
    assignmentId: string;
    reason: string;
    expiresAt: Date;
  }) {
    const a = await this.control.staffRoleAssignment.findUnique({
      where: { id: input.assignmentId },
      include: { role: true },
    });
    if (
      !a ||
      a.revokedAt ||
      a.kind !== 'ELIGIBLE' ||
      a.principalType !== 'STAFF' ||
      a.principalId !== input.staffId ||
      a.role.archivedAt
    )
      throw new ForbiddenException({
        code: 'not_eligible',
        message: 'You are not eligible for this role.',
      });
    await this.closeExpiredElevations(input.staffId);
    const row = await this.control.$transaction(async (tx) => {
      const created = await tx.staffElevation
        .create({
          data: {
            staffId: input.staffId,
            assignmentId: a.id,
            roleId: a.roleId,
            reason: input.reason,
            expiresAt: input.expiresAt,
          },
        })
        .catch((e: { code?: string }) => {
          if (e.code === 'P2002')
            throw new ConflictException({
              code: 'elevation_active',
              message: 'You already have an active elevation.',
            });
          throw e;
        });
      await this.audit.append(
        {
          staffId: input.staffId,
          action: 'staff.elevation_started',
          targetType: 'ROLE',
          targetId: a.roleId,
          data: {
            elevationId: created.id,
            roleKey: a.role.key,
            reason: input.reason,
            expiresAt: input.expiresAt.toISOString(),
          },
        },
        tx,
      );
      return created;
    });
    try {
      await this.fga.write({
        writes: [
          assigneeTuple(a.roleId, 'STAFF', input.staffId, input.expiresAt),
        ],
      });
    } catch (error) {
      await this.control.staffElevation.update({
        where: { id: row.id },
        data: { endedAt: new Date(), endedBy: PROJECTION_FAILED },
      });
      throw error;
    }
    return row;
  }

  async endElevation(elevationId: string, by: string): Promise<void> {
    const e = await this.control.staffElevation.findUnique({
      where: { id: elevationId },
    });
    if (!e || e.endedAt) throw new NotFoundException('No active elevation');
    await this.fga.write({
      deletes: [assigneeTuple(e.roleId, 'STAFF', e.staffId, e.expiresAt)],
      ignoreMissingDeletes: true,
    });
    await this.control.$transaction(async (tx) => {
      await tx.staffElevation.update({
        where: { id: e.id },
        data: { endedAt: new Date(), endedBy: by },
      });
      await this.audit.append(
        {
          staffId: by,
          action: 'staff.elevation_ended',
          targetType: 'STAFF',
          targetId: e.staffId,
          data: { elevationId: e.id },
        },
        tx,
      );
    });
  }

  /** Tidiness only: an expired elevation already has no power (the tuple condition). */
  async closeExpiredElevations(staffId?: string): Promise<number> {
    const expired = await this.control.staffElevation.findMany({
      where: {
        endedAt: null,
        expiresAt: { lte: new Date() },
        ...(staffId ? { staffId } : {}),
      },
    });
    if (!expired.length) return 0;
    await this.fga.write({
      deletes: expired.map((e) =>
        assigneeTuple(e.roleId, 'STAFF', e.staffId, e.expiresAt),
      ),
      ignoreMissingDeletes: true,
    });
    for (const e of expired)
      await this.control.staffElevation.update({
        where: { id: e.id },
        data: { endedAt: e.expiresAt, endedBy: 'system:expired' },
      });
    return expired.length;
  }

  /**
   * Creates a custom role or a new version of one. AC-31: no Owner-only permission, and the editor
   * cannot hand out a permission they do not hold themselves. The version write and the OpenFGA
   * sync run under one role lock, so concurrent edits project in the order they committed.
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

    return this.withRoleLock(async () => {
      const role = await this.control.$transaction(async (tx) => {
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
      await this.syncRolePermissions(role.id);
      return role;
    });
  }

  /** AC-29 order for groups: the member row commits first; a failed tuple write removes it again. */
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
    });
    try {
      await this.fga.write({
        writes: [
          {
            user: `staff:${staffId}`,
            relation: 'member',
            object: `group:${groupId}`,
          },
        ],
      });
    } catch (error) {
      await this.control.$transaction(async (tx) => {
        await tx.staffGroupMember.delete({
          where: { groupId_staffId: { groupId, staffId } },
        });
        await this.audit.append(
          {
            staffId: null,
            action: 'staff.group_member_add_rolled_back',
            targetType: 'GROUP',
            targetId: groupId,
            data: { staffId, reason: 'openfga_write_failed' },
          },
          tx,
        );
      });
      throw error;
    }
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

  /**
   * Holds the role lock for the whole of `fn`: an outer transaction keeps the advisory lock while
   * `fn` commits its own transactions and syncs OpenFGA, so role edits and their projection are
   * serialised (security review 4 Nov).
   */
  private withRoleLock<T>(fn: () => Promise<T>): Promise<T> {
    return this.control.$transaction(
      async (outer) => {
        await outer.$executeRaw`SELECT pg_advisory_xact_lock(hashtext('staff_roles'))`;
        return fn();
      },
      { timeout: 30_000 },
    );
  }

  /** Makes the role's permission tuples exactly its CURRENT version (read under the role lock). */
  private async syncRolePermissions(roleId: string): Promise<void> {
    const role = await this.control.staffRole.findUniqueOrThrow({
      where: { id: roleId },
      include: { versions: true },
    });
    const current = role.versions.find(
      (v) => v.version === role.currentVersion,
    );
    const perms = role.archivedAt
      ? []
      : (current?.permissions ?? []).filter(isStaffPermission);
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
    const liveEligible = new Map(
      (
        await this.control.staffRoleAssignment.findMany({
          where: {
            id: { in: elevations.map((e) => e.assignmentId) },
            kind: 'ELIGIBLE',
            revokedAt: null,
            role: { archivedAt: null },
          },
          select: { id: true, roleId: true, principalId: true },
        })
      ).map((a) => [a.id, a]),
    );
    for (const e of elevations) {
      const a = liveEligible.get(e.assignmentId);
      if (a && a.roleId === e.roleId && a.principalId === e.staffId)
        desired.push(assigneeTuple(e.roleId, 'STAFF', e.staffId, e.expiresAt));
    }
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
