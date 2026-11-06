import { Injectable, Optional } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { canGrantRole, privilegeRank } from '../auth/role-privilege';
import type { RoleName } from '../auth/roles';
import { AuthCache } from '../database/auth-cache.service';
import { ControlPrismaService } from '../database/control-prisma.service';
import { rolesOf, splitRoles } from '../auth/membership.service';
import {
  CursorPage,
  DecodedCursor,
  cursorWhereClause,
  toCursorPage,
} from '../common/pagination/cursor-pagination';
import { withOwnerLock, withWorkspaceLock } from './last-owner';
import {
  LastOwnerError,
  PrivilegeEscalationError,
  UserNotFoundError,
} from './users.errors';

export interface ListUsersInput {
  limit: number;
  cursor?: DecodedCursor;
}

export interface UserSummary {
  id: string;
  keycloakSubject: string;
  email: string;
  displayName: string;
  createdAt: Date;
  lastSeenAt: Date;
  roles: { role: RoleName; grantedAt: Date; grantedBy: string }[];
}

export interface GrantRoleInput {
  tenantId: string;
  /** Issuer of the caller (a workspace's members share its issuer). */
  issuer: string;
  targetUserId: string;
  role: RoleName;
  /** The authenticated caller performing the grant — `AuthContext.user.id`. */
  grantedByUserId: string;
  /** The authenticated caller's own current roles — what the privilege-escalation guard checks `role` against. */
  grantedByRoles: RoleName[];
}

export interface RevokeRoleInput {
  tenantId: string;
  issuer: string;
  targetUserId: string;
  role: RoleName;
  revokedByUserId: string;
  /** The authenticated caller's own current roles — what the privilege-escalation guard checks `role` against (see `revokeRole`'s doc comment: applied symmetrically with `grantRole`). */
  revokedByRoles: RoleName[];
}

type MembershipRow = {
  subject: string;
  role: string;
  extraRoles: string[];
  status: string;
  grantedBy: string | null;
  createdAt: Date;
  updatedAt: Date;
};

type ProfileRow = {
  id: string;
  keycloakSubject: string;
  email: string;
  displayName: string;
  createdAt: Date;
  lastSeenAt: Date;
};

/** Roles come from the workspace Membership (control DB). Only an ACTIVE Membership holds any. */
function toUserSummary(
  row: ProfileRow,
  membership: MembershipRow | undefined,
): UserSummary {
  const roles =
    membership?.status === 'ACTIVE'
      ? rolesOf(membership).sort((a, b) => privilegeRank(a) - privilegeRank(b))
      : [];
  return {
    id: row.id,
    keycloakSubject: row.keycloakSubject,
    email: row.email,
    displayName: row.displayName,
    createdAt: row.createdAt,
    lastSeenAt: row.lastSeenAt,
    roles: roles.map((role) => ({
      role,
      grantedAt: membership?.updatedAt ?? row.createdAt,
      grantedBy: membership?.grantedBy ?? 'system',
    })),
  };
}

/**
 * `GET /users` and role grant/revoke for one workspace. Roles live in the control DB's
 * `Membership` (spec 4.1): nothing here reads a token's roles or writes Keycloak realm roles, and
 * the tenant's `RoleBinding` table is no longer consulted. The privilege-escalation guard
 * (`src/auth/role-privilege.ts`) still runs before any write.
 */
@Injectable()
export class UsersService {
  constructor(
    private readonly auditService: AuditService,
    private readonly control: ControlPrismaService,
    @Optional() private readonly authCache?: AuthCache,
  ) {}

  private membershipsFor(tenantId: string, issuer: string, subjects: string[]) {
    return this.control.membership.findMany({
      where: { tenantId, issuer, subject: { in: subjects } },
    });
  }

  /** `GET /users`: cursor-paginated, newest first, each row with its Membership roles. */
  async listUsers(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    issuer: string,
    input: ListUsersInput,
  ): Promise<CursorPage<UserSummary>> {
    const where = cursorWhereClause('createdAt', input.cursor) ?? {};
    const rows = await tenantClient.userProfile.findMany({
      where,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: input.limit + 1,
    });
    const page = toCursorPage(rows, input.limit, (row) => row.createdAt);
    const memberships = await this.membershipsFor(
      tenantId,
      issuer,
      page.items.map((r) => r.keycloakSubject),
    );
    const bySubject = new Map(memberships.map((m) => [m.subject, m]));
    return {
      items: page.items.map((r) =>
        toUserSummary(r, bySubject.get(r.keycloakSubject)),
      ),
      nextCursor: page.nextCursor,
    };
  }

  /** `GET /users/:id`. */
  async getUserOrThrow(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    issuer: string,
    userId: string,
  ): Promise<UserSummary> {
    const row = await tenantClient.userProfile.findUnique({
      where: { id: userId },
    });
    if (!row) throw new UserNotFoundError(userId);
    const [membership] = await this.membershipsFor(tenantId, issuer, [
      row.keycloakSubject,
    ]);
    return toUserSummary(row, membership);
  }

  /** `POST /users/:id/role-bindings`. Privilege check first, then the Membership write, then audit. */
  async grantRole(
    tenantClient: TenantPrismaClient,
    input: GrantRoleInput,
  ): Promise<UserSummary> {
    if (!canGrantRole(input.grantedByRoles, input.role)) {
      throw new PrivilegeEscalationError(
        'grant',
        input.role,
        input.grantedByRoles,
      );
    }
    const target = await tenantClient.userProfile.findUnique({
      where: { id: input.targetUserId },
    });
    if (!target) throw new UserNotFoundError(input.targetUserId);

    const key = {
      issuer_subject_tenantId: {
        issuer: input.issuer,
        subject: target.keycloakSubject,
        tenantId: input.tenantId,
      },
    };
    await withWorkspaceLock(this.control, input.tenantId, async (tx) => {
      // Fresh read under the workspace lock: the role set is computed from this row only, so a
      // concurrent revoke or grant can never be overwritten with a stale set.
      const existing = await tx.membership.findUnique({ where: key });
      const held = existing?.status === 'ACTIVE' ? rolesOf(existing) : [];
      const split = splitRoles([...held, input.role]);
      if (!split) throw new UserNotFoundError(input.targetUserId);
      await tx.membership.upsert({
        where: key,
        create: {
          issuer: input.issuer,
          subject: target.keycloakSubject,
          tenantId: input.tenantId,
          ...split,
          status: 'ACTIVE',
          email: target.email || null,
          displayName: target.displayName,
          grantedBy: input.grantedByUserId,
        },
        update: {
          ...split,
          status: 'ACTIVE',
          grantedBy: input.grantedByUserId,
        },
      });
    });
    void this.authCache?.invalidate(); // after the commit

    await this.auditService.recordSafely(tenantClient, input.tenantId, {
      eventType: AUDIT_EVENT_TYPES.USER_ROLE_GRANTED,
      actor: { type: 'human', id: input.grantedByUserId },
      data: { targetUserId: input.targetUserId, role: input.role },
    });
    return this.getUserOrThrow(
      tenantClient,
      input.tenantId,
      input.issuer,
      input.targetUserId,
    );
  }

  /**
   * `DELETE /users/:id/role-bindings/:role`. Idempotent; same privilege check as grant. Revoking
   * the last role removes the Membership (the user loses access to the workspace).
   */
  async revokeRole(
    tenantClient: TenantPrismaClient,
    input: RevokeRoleInput,
  ): Promise<UserSummary> {
    if (!canGrantRole(input.revokedByRoles, input.role)) {
      throw new PrivilegeEscalationError(
        'revoke',
        input.role,
        input.revokedByRoles,
      );
    }
    const target = await tenantClient.userProfile.findUnique({
      where: { id: input.targetUserId },
    });
    if (!target) throw new UserNotFoundError(input.targetUserId);

    const key = {
      issuer_subject_tenantId: {
        issuer: input.issuer,
        subject: target.keycloakSubject,
        tenantId: input.tenantId,
      },
    };
    // Re-reads the membership under the workspace lock and computes the new set from that row.
    const write = async (db: Pick<ControlPrismaService, 'membership'>) => {
      const existing = await db.membership.findUnique({ where: key });
      if (existing?.status !== 'ACTIVE') return;
      const split = splitRoles(
        rolesOf(existing).filter((r) => r !== input.role),
      );
      await db.membership.update({
        where: key,
        data: split
          ? { ...split, grantedBy: input.revokedByUserId }
          : {
              status: 'REMOVED',
              extraRoles: [],
              grantedBy: input.revokedByUserId,
            },
      });
    };
    try {
      if (input.role === 'TENANT_OWNER') {
        // The owner count and the write sit under the same lock (#53).
        await withOwnerLock(
          this.control,
          input.tenantId,
          { issuer: input.issuer, subject: target.keycloakSubject },
          write,
        );
      } else {
        await withWorkspaceLock(this.control, input.tenantId, write);
      }
    } catch (error) {
      if (error instanceof LastOwnerError) {
        await this.auditService.recordSafely(tenantClient, input.tenantId, {
          eventType: AUDIT_EVENT_TYPES.USER_ROLE_REVOKE_REFUSED,
          actor: { type: 'human', id: input.revokedByUserId },
          data: {
            targetUserId: input.targetUserId,
            role: input.role,
            reason: 'last_owner',
          },
        });
      }
      throw error;
    }
    void this.authCache?.invalidate(); // after the commit

    await this.auditService.recordSafely(tenantClient, input.tenantId, {
      eventType: AUDIT_EVENT_TYPES.USER_ROLE_REVOKED,
      actor: { type: 'human', id: input.revokedByUserId },
      data: { targetUserId: input.targetUserId, role: input.role },
    });
    return this.getUserOrThrow(
      tenantClient,
      input.tenantId,
      input.issuer,
      input.targetUserId,
    );
  }
}
