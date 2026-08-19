import { Injectable } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { canGrantRole } from '../auth/role-privilege';
import type { RoleName } from '../auth/roles';
import { ControlPrismaService } from '../database/control-prisma.service';
import { KeycloakAdminClient } from '../keycloak/keycloak-admin.client';
import {
  CursorPage,
  DecodedCursor,
  cursorWhereClause,
  toCursorPage,
} from '../common/pagination/cursor-pagination';
import {
  PrivilegeEscalationError,
  TenantRealmNotProvisionedError,
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
  targetUserId: string;
  role: RoleName;
  /** The authenticated caller performing the grant — `AuthContext.user.id`. */
  grantedByUserId: string;
  /** The authenticated caller's own current roles — what the privilege-escalation guard checks `role` against. */
  grantedByRoles: RoleName[];
}

export interface RevokeRoleInput {
  tenantId: string;
  targetUserId: string;
  role: RoleName;
  revokedByUserId: string;
  /** The authenticated caller's own current roles — what the privilege-escalation guard checks `role` against (see `revokeRole`'s doc comment: applied symmetrically with `grantRole`). */
  revokedByRoles: RoleName[];
}

const ROLE_BINDING_INCLUDE = {
  roleBindings: { orderBy: { role: 'asc' as const } },
};

function toUserSummary(row: {
  id: string;
  keycloakSubject: string;
  email: string;
  displayName: string;
  createdAt: Date;
  lastSeenAt: Date;
  roleBindings: { role: string; grantedAt: Date; grantedBy: string }[];
}): UserSummary {
  return {
    id: row.id,
    keycloakSubject: row.keycloakSubject,
    email: row.email,
    displayName: row.displayName,
    createdAt: row.createdAt,
    lastSeenAt: row.lastSeenAt,
    roles: row.roleBindings.map((binding) => ({
      role: binding.role as RoleName,
      grantedAt: binding.grantedAt,
      grantedBy: binding.grantedBy,
    })),
  };
}

/**
 * Phase 14 (Users/Roles/Settings) — `GET /users`'s backing rows (the
 * `UserProfile`/`RoleBinding` models `JwtAuthGuard` has found-or-created
 * and synced since Phase 3, see docs/human-auth.md) plus the one new
 * mutating capability this phase adds: a Manar-side role grant/revoke
 * surface with its own privilege-escalation guard
 * (`src/auth/role-privilege.ts`).
 *
 * **Keycloak stays the role-assignment source of truth** — `grantRole`/
 * `revokeRole` call `KeycloakAdminClient.assignRealmRole`/`removeRealmRole`
 * *before* touching the local `RoleBinding` row, for exactly the reason
 * `JwtAuthGuard.syncRoleBindings`'s doc comment already establishes: that
 * guard reconciles every authenticated user's `RoleBinding` rows to match
 * their JWT's `realm_access.roles` claim on *every* request. A grant that
 * only ever touched the local row would be silently reverted the next
 * time the affected user authenticates, since Keycloak would have no
 * record of it. Writing to Keycloak first (and only writing the local row
 * once that succeeds) keeps the two in agreement rather than letting them
 * drift and then get forcibly reconciled out from under the caller.
 */
@Injectable()
export class UsersService {
  constructor(
    private readonly auditService: AuditService,
    private readonly control: ControlPrismaService,
    private readonly keycloakAdminClient: KeycloakAdminClient,
  ) {}

  /** `GET /users` — cursor-paginated, newest first, each row including its current `RoleBinding`s. */
  async listUsers(
    tenantClient: TenantPrismaClient,
    input: ListUsersInput,
  ): Promise<CursorPage<UserSummary>> {
    const where = cursorWhereClause('createdAt', input.cursor) ?? {};
    const rows = await tenantClient.userProfile.findMany({
      where,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: input.limit + 1,
      include: ROLE_BINDING_INCLUDE,
    });
    const page = toCursorPage(rows, input.limit, (row) => row.createdAt);
    return {
      items: page.items.map(toUserSummary),
      nextCursor: page.nextCursor,
    };
  }

  /** `GET /users/:id`. */
  async getUserOrThrow(
    tenantClient: TenantPrismaClient,
    userId: string,
  ): Promise<UserSummary> {
    const row = await tenantClient.userProfile.findUnique({
      where: { id: userId },
      include: ROLE_BINDING_INCLUDE,
    });
    if (!row) throw new UserNotFoundError(userId);
    return toUserSummary(row);
  }

  /**
   * `POST /users/:id/role-bindings`. Enforces the privilege-escalation
   * guard (`canGrantRole`) *before* ever calling Keycloak or writing any
   * row — a caller can never grant a role more privileged than any role
   * they themselves currently hold, regardless of the endpoint's own
   * coarse `@RequireRole('TENANT_OWNER', 'SECURITY_ADMIN')` gate (see
   * `PrivilegeEscalationError`'s doc comment for why that gate alone
   * isn't enough).
   */
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

    const targetUser = await tenantClient.userProfile.findUnique({
      where: { id: input.targetUserId },
    });
    if (!targetUser) throw new UserNotFoundError(input.targetUserId);

    const tenant = await this.control.tenant.findUnique({
      where: { id: input.tenantId },
    });
    if (!tenant?.keycloakRealm) {
      throw new TenantRealmNotProvisionedError(input.tenantId);
    }

    await this.keycloakAdminClient.assignRealmRole(
      tenant.keycloakRealm,
      targetUser.keycloakSubject,
      input.role,
    );

    await tenantClient.roleBinding.upsert({
      where: { userId_role: { userId: input.targetUserId, role: input.role } },
      create: {
        userId: input.targetUserId,
        role: input.role,
        grantedBy: input.grantedByUserId,
      },
      // Already held locally (e.g. re-granting an existing role) -- the
      // Keycloak call above is what actually matters; leave the original
      // grantedAt/grantedBy as the historical record rather than
      // overwriting it on every idempotent re-grant.
      update: {},
    });

    await this.auditService.recordSafely(tenantClient, input.tenantId, {
      eventType: AUDIT_EVENT_TYPES.USER_ROLE_GRANTED,
      actor: { type: 'human', id: input.grantedByUserId },
      data: { targetUserId: input.targetUserId, role: input.role },
    });

    return this.getUserOrThrow(tenantClient, input.targetUserId);
  }

  /**
   * `DELETE /users/:id/role-bindings/:role`. Idempotent, same posture as
   * `KeycloakAdminClient.removeRealmRole`: revoking a role the target
   * doesn't currently hold still succeeds as a no-op (the privilege check
   * below runs regardless of the target's current state, since it's a
   * property of the *role being acted on*, not of whether this particular
   * call happens to change anything).
   *
   * Enforces the identical privilege-escalation guard `grantRole` does,
   * applied to revoke rather than grant: a caller can never revoke a role
   * more privileged than any role they themselves currently hold. Without
   * this, the endpoint's coarse `@RequireRole('TENANT_OWNER',
   * 'SECURITY_ADMIN')` gate alone would let any `SECURITY_ADMIN` strip
   * `TENANT_OWNER` from the actual tenant owner (or remove another
   * `SECURITY_ADMIN`'s/`AUDITOR`'s role to cover their tracks) — the same
   * class of bug the grant-side guard exists to prevent, just on the
   * other verb.
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

    const targetUser = await tenantClient.userProfile.findUnique({
      where: { id: input.targetUserId },
    });
    if (!targetUser) throw new UserNotFoundError(input.targetUserId);

    const tenant = await this.control.tenant.findUnique({
      where: { id: input.tenantId },
    });
    if (!tenant?.keycloakRealm) {
      throw new TenantRealmNotProvisionedError(input.tenantId);
    }

    await this.keycloakAdminClient.removeRealmRole(
      tenant.keycloakRealm,
      targetUser.keycloakSubject,
      input.role,
    );

    await tenantClient.roleBinding.deleteMany({
      where: { userId: input.targetUserId, role: input.role },
    });

    await this.auditService.recordSafely(tenantClient, input.tenantId, {
      eventType: AUDIT_EVENT_TYPES.USER_ROLE_REVOKED,
      actor: { type: 'human', id: input.revokedByUserId },
      data: { targetUserId: input.targetUserId, role: input.role },
    });

    return this.getUserOrThrow(tenantClient, input.targetUserId);
  }
}
