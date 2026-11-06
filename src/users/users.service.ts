import { Injectable } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { canGrantRole, privilegeRank } from '../auth/role-privilege';
import type { RoleName } from '../auth/roles';
import { ControlPrismaService } from '../database/control-prisma.service';
import { rolesOf, splitRoles } from '../auth/membership.service';
import {
  CursorPage,
  DecodedCursor,
  cursorWhereClause,
  toCursorPage,
} from '../common/pagination/cursor-pagination';
import { withOwnerLock } from './last-owner';
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

    const [existing] = await this.membershipsFor(input.tenantId, input.issuer, [
      target.keycloakSubject,
    ]);
    const held = existing?.status === 'ACTIVE' ? rolesOf(existing) : [];
    const split = splitRoles([...held, input.role]);
    if (!split) throw new UserNotFoundError(input.targetUserId);
    await this.control.membership.upsert({
      where: {
        issuer_subject_tenantId: {
          issuer: input.issuer,
          subject: target.keycloakSubject,
          tenantId: input.tenantId,
        },
      },
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
      update: { ...split, status: 'ACTIVE', grantedBy: input.grantedByUserId },
    });

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

    const [existing] = await this.membershipsFor(input.tenantId, input.issuer, [
      target.keycloakSubject,
    ]);
    if (existing?.status === 'ACTIVE') {
      const split = splitRoles(
        rolesOf(existing).filter((r) => r !== input.role),
      );
      const write = (db: Pick<ControlPrismaService, 'membership'>) =>
        db.membership.update({
          where: {
            issuer_subject_tenantId: {
              issuer: input.issuer,
              subject: target.keycloakSubject,
              tenantId: input.tenantId,
            },
          },
          data: split
            ? { ...split, grantedBy: input.revokedByUserId }
            : {
                status: 'REMOVED',
                extraRoles: [],
                grantedBy: input.revokedByUserId,
              },
        });
      if (
        input.role === 'TENANT_OWNER' &&
        rolesOf(existing).includes(input.role)
      ) {
        try {
          await withOwnerLock(
            this.control,
            input.tenantId,
            { issuer: input.issuer, subject: target.keycloakSubject },
            write,
          );
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
      } else {
        await write(this.control);
      }
    }

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
