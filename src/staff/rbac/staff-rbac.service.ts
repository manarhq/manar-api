import {
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  Optional,
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
  Prisma,
  StaffElevation,
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

/** Tells the staff Owners about something that needs a person (email and push; spec §11.4). */
export interface StaffAlerts {
  alertOwners(kind: string, data: Record<string, unknown>): Promise<void>;
}
export const STAFF_ALERTS = Symbol('STAFF_ALERTS');
/** `revokedBy` / `endedBy` when the OpenFGA projection of a grant failed and it was rolled back. */
export const PROJECTION_FAILED = 'system:projection_failed';
/** Spec §11.1: an elevation lasts at most one hour. */
export const MAX_ELEVATION_MS = 60 * 60 * 1000;

const reconcileFixed = new Counter({
  name: 'rbac_reconcile_fixed_total',
  help: 'OpenFGA staff tuples the reconciler had to repair towards Postgres',
});

type Tx = Prisma.TransactionClient;
interface Changes {
  writes: number;
  deletes: number;
}
const NO_CHANGES: Changes = { writes: 0, deletes: 0 };
const plus = (a: Changes, b: Changes): Changes => ({
  writes: a.writes + b.writes,
  deletes: a.deletes + b.deletes,
});
type PrincipalType = 'STAFF' | 'GROUP';

export interface GrantInput {
  roleId: string;
  principalType: PrincipalType;
  principalId: string;
  kind: 'ACTIVE' | 'ELIGIBLE';
  expiresAt?: Date;
  grantedBy: string;
  changeRequestId?: string;
}

const principalUser = (type: PrincipalType, id: string) =>
  type === 'STAFF' ? `staff:${id}` : `group:${id}#member`;

/** The `role#assignee` tuple an ACTIVE assignment (or an elevation) projects to. */
export function assigneeTuple(
  roleId: string,
  principalType: PrincipalType,
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

const memberTuple = (groupId: string, staffId: string): TupleKey => ({
  user: `staff:${staffId}`,
  relation: 'member',
  object: `group:${groupId}`,
});

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
 * projection every check reads (AC-30: no cache).
 *
 * One rule for every write path (security review, 4 Nov): Postgres changes and OpenFGA writes for
 * a (principal, role) pair or a (staff, group) pair happen only inside `withLock`, which holds a
 * transaction-scoped advisory lock on the SAME transaction client that does the work. OpenFGA is
 * then made to match the state that transaction can see by `project*()`. So:
 *   - a grant commits its row first and projects it in a second locked transaction (a tuple never
 *     exists for a row that rolled back); a failed projection revokes the row and deletes the tuple;
 *   - a revoke updates the row and projects (deletes) before its commit, so the tuple is gone
 *     before Postgres says revoked (AC-29) and nothing can re-add it while the lock is held;
 *   - the reconciler repairs through the same projection under the same lock.
 * Role permission tuples are synced with a compare-and-set on `currentVersion`.
 */
@Injectable()
export class StaffRbacService {
  private readonly logger = new Logger(StaffRbacService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly fga: OpenFgaClientService,
    private readonly audit: StaffAuditService,
    @Optional() @Inject(STAFF_ALERTS) private readonly alerts?: StaffAlerts,
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

  // ---------------------------------------------------------------------------------------------
  // The lock and the projection
  // ---------------------------------------------------------------------------------------------

  /** Runs `fn` in one transaction holding the advisory lock for `key`; all work uses `tx`. */
  private withLock<T>(key: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
    return this.control.$transaction(
      async (tx) => {
        await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${key}))`;
        return fn(tx);
      },
      { timeout: 30_000 },
    );
  }

  private assignmentLock(principalId: string, roleId: string) {
    return `staff_rbac:assign:${principalId}:${roleId}`;
  }

  private memberLock(staffId: string, groupId: string) {
    return `staff_rbac:member:${staffId}:${groupId}`;
  }

  /**
   * The tuple (principal, role) should have right now, from what `tx` can see: a live ACTIVE
   * assignment, else (staff only) a live elevation resting on a live ELIGIBLE assignment.
   */
  private async desiredAssignee(
    tx: Tx,
    principalType: PrincipalType,
    principalId: string,
    roleId: string,
    now: Date,
  ): Promise<TupleKey | null> {
    const role = await tx.staffRole.findUnique({ where: { id: roleId } });
    if (!role || role.archivedAt) return null;
    const active = await tx.staffRoleAssignment.findFirst({
      where: {
        roleId,
        principalType,
        principalId,
        kind: 'ACTIVE',
        revokedAt: null,
        OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
      },
      orderBy: { createdAt: 'asc' },
    });
    if (active)
      return assigneeTuple(
        roleId,
        principalType,
        principalId,
        active.expiresAt,
      );
    if (principalType !== 'STAFF') return null;
    const elevation = await tx.staffElevation.findFirst({
      where: {
        staffId: principalId,
        roleId,
        endedAt: null,
        expiresAt: { gt: now },
      },
    });
    if (!elevation) return null;
    const eligible = await tx.staffRoleAssignment.findUnique({
      where: { id: elevation.assignmentId },
    });
    const live =
      !!eligible &&
      eligible.kind === 'ELIGIBLE' &&
      !eligible.revokedAt &&
      eligible.roleId === roleId &&
      eligible.principalId === principalId &&
      (!eligible.expiresAt ||
        (eligible.expiresAt > now &&
          elevation.expiresAt <= eligible.expiresAt));
    return live
      ? assigneeTuple(roleId, 'STAFF', principalId, elevation.expiresAt)
      : null;
  }

  /** Makes OpenFGA hold exactly `desired` for this (user, object). Returns what it changed. */
  private async converge(
    user: string,
    object: string,
    desired: TupleKey | null,
    dryRun = false,
  ): Promise<Changes> {
    const actual = await this.fga.readTuples({ object, user });
    const stale = actual.filter(
      (t) => !desired || tupleKey(t) !== tupleKey(desired),
    );
    const missing =
      !!desired && !actual.some((t) => tupleKey(t) === tupleKey(desired));
    const changes = { writes: missing ? 1 : 0, deletes: stale.length };
    if (dryRun) return changes;
    // Deletes first, in their own call: OpenFGA refuses a request that deletes and writes the
    // same (user, relation, object) with different conditions.
    if (stale.length)
      await this.fga.write({ deletes: stale, ignoreMissingDeletes: true });
    if (missing && desired) await this.fga.write({ writes: [desired] });
    return changes;
  }

  private async projectAssignee(
    tx: Tx,
    principalType: PrincipalType,
    principalId: string,
    roleId: string,
    dryRun = false,
  ): Promise<Changes> {
    const desired = await this.desiredAssignee(
      tx,
      principalType,
      principalId,
      roleId,
      new Date(),
    );
    return this.converge(
      principalUser(principalType, principalId),
      roleObject(roleId),
      desired,
      dryRun,
    );
  }

  private async projectMember(
    tx: Tx,
    groupId: string,
    staffId: string,
    dryRun = false,
  ): Promise<Changes> {
    const row = await tx.staffGroupMember.findUnique({
      where: { groupId_staffId: { groupId, staffId } },
    });
    return this.converge(
      `staff:${staffId}`,
      `group:${groupId}`,
      row ? memberTuple(groupId, staffId) : null,
      dryRun,
    );
  }

  // ---------------------------------------------------------------------------------------------
  // Role assignments
  // ---------------------------------------------------------------------------------------------

  async grant(input: GrantInput): Promise<StaffRoleAssignment> {
    const lock = this.assignmentLock(input.principalId, input.roleId);
    const row = await this.withLock(lock, async (tx) => {
      const role = await tx.staffRole.findUnique({
        where: { id: input.roleId },
      });
      if (!role || role.archivedAt) throw new NotFoundException('Unknown role');
      // Groups never hold Owner or a custom role (security review, 4 Nov): a membership change would
      // grant them without the two-person rule those grants need.
      if (
        input.principalType === 'GROUP' &&
        (role.key === 'owner' || !role.builtIn)
      )
        throw new ForbiddenException({
          code: 'group_cannot_hold_role',
          message:
            'Groups cannot hold the Owner role or a custom role. Grant it to the person.',
        });
      if (input.expiresAt && input.expiresAt <= new Date())
        throw new ConflictException({
          code: 'already_expired',
          message: 'The end time is in the past.',
        });
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
      if (input.kind === 'ACTIVE' && input.principalType === 'STAFF') {
        const elevated = await tx.staffElevation.findFirst({
          where: {
            staffId: input.principalId,
            roleId: input.roleId,
            endedAt: null,
            expiresAt: { gt: new Date() },
          },
        });
        if (elevated)
          throw new ConflictException({
            code: 'elevation_active',
            message: 'End the current elevation to this role first.',
          });
      }
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
          staffId: input.grantedBy.startsWith('system')
            ? null
            : input.grantedBy,
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
    if (input.kind === 'ELIGIBLE') return row; // no power until an elevation
    try {
      await this.withLock(lock, (tx) =>
        this.projectAssignee(
          tx,
          input.principalType,
          input.principalId,
          input.roleId,
        ),
      );
    } catch (error) {
      await this.rollBackGrant(row);
      throw error;
    }
    return row;
  }

  /** The grant's projection failed: revoke the row and remove any tuple (best effort). */
  private async rollBackGrant(a: StaffRoleAssignment): Promise<void> {
    await this.withLock(
      this.assignmentLock(a.principalId, a.roleId),
      async (tx) => {
        await tx.staffRoleAssignment.update({
          where: { id: a.id },
          data: { revokedAt: new Date(), revokedBy: PROJECTION_FAILED },
        });
        await this.audit.append(
          {
            staffId: null,
            action: 'staff.role_grant_rolled_back',
            data: { assignmentId: a.id, reason: 'openfga_write_failed' },
          },
          tx,
        );
        await this.projectAssignee(
          tx,
          a.principalType,
          a.principalId,
          a.roleId,
        ).catch((e: unknown) =>
          this.logger.error(
            `could not remove the tuple of rolled-back grant ${a.id}; the reconciler will: ${String(e)}`,
          ),
        );
      },
    );
  }

  /**
   * Revokes an assignment. Revoking an ELIGIBLE one also ends every open elevation resting on it.
   * The tuple is removed before this transaction commits (AC-29: revocations hit OpenFGA first).
   */
  async revoke(assignmentId: string, by: string): Promise<void> {
    const peek = await this.control.staffRoleAssignment.findUnique({
      where: { id: assignmentId },
    });
    if (!peek) throw new NotFoundException('Unknown assignment');
    await this.withLock(
      this.assignmentLock(peek.principalId, peek.roleId),
      async (tx) => {
        await tx.$queryRaw`SELECT id FROM staff_role_assignments WHERE id = ${assignmentId} FOR UPDATE`;
        const a = await tx.staffRoleAssignment.findUniqueOrThrow({
          where: { id: assignmentId },
        });
        if (a.revokedAt) throw new NotFoundException('Unknown assignment');
        const now = new Date();
        const ended = await tx.staffElevation.updateMany({
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
              elevationsEnded: ended.count,
            },
          },
          tx,
        );
        await this.projectAssignee(
          tx,
          a.principalType,
          a.principalId,
          a.roleId,
        );
      },
    );
  }

  // ---------------------------------------------------------------------------------------------
  // Elevations (spec §11.1)
  // ---------------------------------------------------------------------------------------------

  /**
   * Turns the caller's ELIGIBLE assignment on until `expiresAt`, clamped to one hour and to the
   * eligibility's own expiry. Refuses an expired eligibility and an end time already past.
   */
  async startElevation(input: {
    staffId: string;
    assignmentId: string;
    reason: string;
    expiresAt: Date;
  }): Promise<StaffElevation> {
    const peek = await this.control.staffRoleAssignment.findUnique({
      where: { id: input.assignmentId },
    });
    if (!peek) throw notEligible();
    const lock = this.assignmentLock(input.staffId, peek.roleId);
    const row = await this.withLock(lock, async (tx) => {
      await tx.$queryRaw`SELECT id FROM staff_role_assignments WHERE id = ${input.assignmentId} FOR UPDATE`;
      const a = await tx.staffRoleAssignment.findUniqueOrThrow({
        where: { id: input.assignmentId },
        include: { role: true },
      });
      const now = new Date();
      if (
        a.revokedAt ||
        a.kind !== 'ELIGIBLE' ||
        a.principalType !== 'STAFF' ||
        a.principalId !== input.staffId ||
        a.role.archivedAt ||
        (a.expiresAt && a.expiresAt <= now)
      )
        throw notEligible();
      if (input.expiresAt <= now)
        throw new ConflictException({
          code: 'already_expired',
          message: 'The end time is in the past.',
        });
      const expiresAt = new Date(
        Math.min(
          input.expiresAt.getTime(),
          now.getTime() + MAX_ELEVATION_MS,
          a.expiresAt?.getTime() ?? Number.POSITIVE_INFINITY,
        ),
      );
      const holdsActive = await tx.staffRoleAssignment.findFirst({
        where: {
          roleId: a.roleId,
          principalType: 'STAFF',
          principalId: input.staffId,
          kind: 'ACTIVE',
          revokedAt: null,
          OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
        },
      });
      if (holdsActive)
        throw new ConflictException({
          code: 'already_active',
          message: 'You already hold this role.',
        });
      // Expired elevations still open are closed so the one-open-elevation index admits this one.
      await tx.staffElevation.updateMany({
        where: {
          staffId: input.staffId,
          endedAt: null,
          expiresAt: { lte: now },
        },
        data: { endedAt: now, endedBy: 'system:expired' },
      });
      const open = await tx.staffElevation.findFirst({
        where: { staffId: input.staffId, endedAt: null },
      });
      if (open)
        throw new ConflictException({
          code: 'elevation_active',
          message: 'You already have an active elevation.',
        });
      const created = await tx.staffElevation.create({
        data: {
          staffId: input.staffId,
          assignmentId: a.id,
          roleId: a.roleId,
          reason: input.reason,
          expiresAt,
        },
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
            expiresAt: expiresAt.toISOString(),
          },
        },
        tx,
      );
      return created;
    });
    try {
      await this.withLock(lock, (tx) =>
        this.projectAssignee(tx, 'STAFF', input.staffId, row.roleId),
      );
    } catch (error) {
      await this.withLock(lock, async (tx) => {
        await tx.staffElevation.update({
          where: { id: row.id },
          data: { endedAt: new Date(), endedBy: PROJECTION_FAILED },
        });
        await this.projectAssignee(
          tx,
          'STAFF',
          input.staffId,
          row.roleId,
        ).catch(() => NO_CHANGES);
      });
      throw error;
    }
    return row;
  }

  async endElevation(elevationId: string, by: string): Promise<void> {
    const peek = await this.control.staffElevation.findUnique({
      where: { id: elevationId },
    });
    if (!peek) throw new NotFoundException('No active elevation');
    await this.withLock(
      this.assignmentLock(peek.staffId, peek.roleId),
      async (tx) => {
        await tx.$queryRaw`SELECT id FROM staff_elevations WHERE id = ${elevationId} FOR UPDATE`;
        const e = await tx.staffElevation.findUniqueOrThrow({
          where: { id: elevationId },
        });
        if (e.endedAt) throw new NotFoundException('No active elevation');
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
        await this.projectAssignee(tx, 'STAFF', e.staffId, e.roleId);
      },
    );
  }

  /** Tidiness only: an expired elevation already has no power (the tuple condition). */
  async closeExpiredElevations(): Promise<number> {
    const expired = await this.control.staffElevation.findMany({
      where: { endedAt: null, expiresAt: { lte: new Date() } },
      select: { id: true, staffId: true, roleId: true },
    });
    for (const e of expired)
      await this.withLock(
        this.assignmentLock(e.staffId, e.roleId),
        async (tx) => {
          await tx.staffElevation.updateMany({
            where: { id: e.id, endedAt: null },
            data: { endedAt: new Date(), endedBy: 'system:expired' },
          });
          await this.projectAssignee(tx, 'STAFF', e.staffId, e.roleId);
        },
      );
    return expired.length;
  }

  // ---------------------------------------------------------------------------------------------
  // Groups
  // ---------------------------------------------------------------------------------------------

  async addGroupMember(groupId: string, staffId: string, by: string) {
    const lock = this.memberLock(staffId, groupId);
    await this.withLock(lock, async (tx) => {
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
      await this.withLock(lock, (tx) =>
        this.projectMember(tx, groupId, staffId),
      );
    } catch (error) {
      await this.withLock(lock, async (tx) => {
        await tx.staffGroupMember.deleteMany({ where: { groupId, staffId } });
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
        await this.projectMember(tx, groupId, staffId).catch(() => NO_CHANGES);
      });
      throw error;
    }
  }

  async removeGroupMember(groupId: string, staffId: string, by: string) {
    await this.withLock(this.memberLock(staffId, groupId), async (tx) => {
      const removed = await tx.staffGroupMember.deleteMany({
        where: { groupId, staffId },
      });
      if (!removed.count) throw new NotFoundException('Not a member');
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
      await this.projectMember(tx, groupId, staffId);
    });
  }

  // ---------------------------------------------------------------------------------------------
  // Roles and their permissions
  // ---------------------------------------------------------------------------------------------

  /** Idempotent: built-in roles exist at the permissions this code defines, tuples included. */
  async ensureBuiltInRoles(): Promise<void> {
    for (const key of BUILT_IN_ROLE_KEYS) {
      const wanted = [...BUILT_IN_ROLES[key]].sort();
      const roleId = await this.withLock('staff_rbac:roles', async (tx) => {
        const role = await tx.staffRole.findUnique({
          where: { key },
          include: { versions: { orderBy: { version: 'desc' }, take: 1 } },
        });
        if (!role) {
          const created = await tx.staffRole.create({
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
          return created.id;
        }
        if (
          JSON.stringify([...(role.versions[0]?.permissions ?? [])].sort()) !==
          JSON.stringify(wanted)
        ) {
          const version = role.currentVersion + 1;
          await tx.staffRoleVersion.create({
            data: {
              roleId: role.id,
              version,
              permissions: wanted,
              createdBy: 'system',
            },
          });
          await tx.staffRole.update({
            where: { id: role.id },
            data: { currentVersion: version },
          });
        }
        return role.id;
      });
      await this.syncRolePermissions(roleId);
    }
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

    const role = await this.withLock('staff_rbac:roles', async (tx) => {
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
  }

  /**
   * Makes the role's permission tuples match its CURRENT version, with a compare-and-set on
   * `currentVersion`: if the version moved while computing or writing, it goes round again, so
   * the last committed version is what OpenFGA ends on. Returns the number of tuples changed.
   */
  async syncRolePermissions(roleId: string, dryRun = false): Promise<Changes> {
    const versionNow = async () =>
      (
        await this.control.staffRole.findUniqueOrThrow({
          where: { id: roleId },
          select: { currentVersion: true },
        })
      ).currentVersion;
    let changed = NO_CHANGES;
    for (let attempt = 0; attempt < 10; attempt++) {
      const role = await this.control.staffRole.findUniqueOrThrow({
        where: { id: roleId },
        include: { versions: true },
      });
      const version = role.currentVersion;
      const current = role.versions.find((v) => v.version === version);
      const perms = role.archivedAt
        ? []
        : (current?.permissions ?? []).filter(isStaffPermission);
      const actual = await this.fga.readTuples({
        object: PLATFORM_OBJECT,
        user: `${roleObject(roleId)}#assignee`,
      });
      const wanted = perms.map((p) => permissionTuple(roleId, p));
      const have = new Set(actual.map(tupleKey));
      const want = new Set(wanted.map(tupleKey));
      const writes = wanted.filter((t) => !have.has(tupleKey(t)));
      const deletes = actual.filter((t) => !want.has(tupleKey(t)));
      const step = { writes: writes.length, deletes: deletes.length };
      if (dryRun) return step;
      if ((await versionNow()) !== version) continue; // moved before we wrote: recompute
      try {
        await this.fga.write({ writes, deletes, ignoreMissingDeletes: true });
      } catch (error) {
        // A concurrent sync of the same role wrote first (OpenFGA answers 409): recompute.
        if (isFgaConflict(error)) continue;
        throw error;
      }
      changed = plus(changed, step);
      if ((await versionNow()) === version) return changed; // still current after the write
    }
    throw new ConflictException({
      code: 'role_sync_contended',
      message: 'The role kept changing; try again.',
    });
  }

  // ---------------------------------------------------------------------------------------------
  // Reconciler (AC-29)
  // ---------------------------------------------------------------------------------------------

  /** A run that would delete more than this many tuples stops and alerts unless told to go on. */
  static MAX_RECONCILE_DELETES = 20;

  /**
   * Repairs OpenFGA towards Postgres. Sweeps every tuple on `platform:manar`, on every staff role
   * object and on every group object (those Postgres knows, and those the tuples name), with no
   * user filter. Recognised (principal, role) and (staff, group) pairs are repaired through the
   * same locked projection the write paths use; anything else (unknown user shapes, unknown
   * relations, roles or groups Postgres does not have) is deleted under a lock.
   *
   * It plans first. If the plan deletes more than MAX_RECONCILE_DELETES tuples, a real run stops,
   * records `rbac.reconcile_blocked` and alerts the Owners, unless `allowMassDelete` is set: a bug
   * in the desired state must not silently remove everyone's access.
   */
  async reconcile(opts: {
    dryRun: boolean;
    allowMassDelete?: boolean;
  }): Promise<{ fixed: number; wouldDelete: number; blocked?: boolean }> {
    const plan = await this.sweep(true);
    if (opts.dryRun)
      return { fixed: plan.writes + plan.deletes, wouldDelete: plan.deletes };
    if (
      plan.deletes > StaffRbacService.MAX_RECONCILE_DELETES &&
      !opts.allowMassDelete
    ) {
      await this.audit.append({
        staffId: null,
        action: 'rbac.reconcile_blocked',
        data: { wouldDelete: plan.deletes, wouldWrite: plan.writes },
      });
      this.logger.error(
        `RBAC reconcile would delete ${plan.deletes} staff tuples; stopped. Run rbac:reconcile --allow-mass-delete after checking.`,
      );
      await this.alerts?.alertOwners('rbac_reconcile_blocked', {
        wouldDelete: plan.deletes,
      });
      return { fixed: 0, wouldDelete: plan.deletes, blocked: true };
    }
    const done = await this.sweep(false);
    const fixed = done.writes + done.deletes;
    if (fixed) {
      reconcileFixed.inc(fixed);
      this.logger.warn(`RBAC reconcile repaired ${fixed} staff tuple(s)`);
    }
    return { fixed, wouldDelete: done.deletes };
  }

  private async sweep(dryRun: boolean): Promise<Changes> {
    let total = NO_CHANGES;
    const [roles, groups] = await Promise.all([
      this.control.staffRole.findMany({
        select: { id: true, archivedAt: true },
      }),
      this.control.staffGroup.findMany({ select: { id: true } }),
    ]);
    const liveRoles = new Set(
      roles.filter((r) => !r.archivedAt).map((r) => r.id),
    );
    const knownRoles = new Set(roles.map((r) => r.id));
    const knownGroups = new Set(groups.map((g) => g.id));

    // 1. platform:manar: each live role's permissions by compare-and-set; the rest is foreign.
    const roleIds = new Set(knownRoles);
    const foreign: TupleKey[] = [];
    for (const t of await this.fga.readObject(PLATFORM_OBJECT)) {
      const m = /^role:(.+)~platform~manar#assignee$/.exec(t.user);
      if (m && liveRoles.has(m[1]!)) continue; // owned by syncRolePermissions below
      if (m) roleIds.add(m[1]!);
      foreign.push(t);
    }
    for (const id of liveRoles)
      total = plus(total, await this.syncRolePermissions(id, dryRun));

    // 2. Every role object, known or named by a tuple.
    const pairs = new Map<
      string,
      { type: PrincipalType; id: string; roleId: string }
    >();
    const addPair = (type: PrincipalType, id: string, roleId: string) =>
      pairs.set(`${type}|${id}|${roleId}`, { type, id, roleId });
    const groupIds = new Set(knownGroups);
    for (const roleId of roleIds)
      for (const t of await this.fga.readObject(roleObject(roleId))) {
        const staff = /^staff:([^#]+)$/.exec(t.user);
        const group = /^group:([^#]+)#member$/.exec(t.user);
        if (t.relation === 'assignee' && staff)
          addPair('STAFF', staff[1]!, roleId);
        else if (t.relation === 'assignee' && group) {
          addPair('GROUP', group[1]!, roleId);
          groupIds.add(group[1]!);
        } else foreign.push(t);
      }
    for (const a of await this.control.staffRoleAssignment.findMany({
      where: { revokedAt: null },
      select: { principalType: true, principalId: true, roleId: true },
    }))
      addPair(a.principalType, a.principalId, a.roleId);
    for (const e of await this.control.staffElevation.findMany({
      where: { endedAt: null },
      select: { staffId: true, roleId: true },
    }))
      addPair('STAFF', e.staffId, e.roleId);
    for (const p of pairs.values())
      total = plus(
        total,
        await this.withLock(this.assignmentLock(p.id, p.roleId), (tx) =>
          this.projectAssignee(tx, p.type, p.id, p.roleId, dryRun),
        ),
      );

    // 3. Every group object, known or named by a tuple.
    const members = new Map<string, { groupId: string; staffId: string }>();
    for (const m of await this.control.staffGroupMember.findMany())
      members.set(`${m.groupId}|${m.staffId}`, m);
    for (const groupId of groupIds)
      for (const t of await this.fga.readObject(`group:${groupId}`)) {
        const staff = /^staff:([^#]+)$/.exec(t.user);
        if (t.relation === 'member' && staff)
          members.set(`${groupId}|${staff[1]}`, {
            groupId,
            staffId: staff[1]!,
          });
        else foreign.push(t);
      }
    for (const m of members.values())
      total = plus(
        total,
        await this.withLock(this.memberLock(m.staffId, m.groupId), (tx) =>
          this.projectMember(tx, m.groupId, m.staffId, dryRun),
        ),
      );

    // 4. Foreign tuples: nothing in Postgres stands behind them.
    if (!dryRun)
      for (const t of foreign)
        await this.withLock(`staff_rbac:sweep:${t.object}`, async () => {
          await this.fga.write({ deletes: [t], ignoreMissingDeletes: true });
        });
    return plus(total, { writes: 0, deletes: foreign.length });
  }
}

function isFgaConflict(error: unknown): boolean {
  const e = error as { statusCode?: unknown; message?: unknown } | null;
  return (
    e?.statusCode === 409 ||
    (typeof e?.message === 'string' && e.message.includes('status code 409'))
  );
}

function notEligible() {
  return new ForbiddenException({
    code: 'not_eligible',
    message: 'You are not eligible for this role.',
  });
}
