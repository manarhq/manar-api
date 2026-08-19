/** Thrown when a `UserProfile` ID doesn't resolve within the caller's tenant database. */
export class UserNotFoundError extends Error {
  constructor(userId: string) {
    super(`User "${userId}" was not found`);
    this.name = 'UserNotFoundError';
  }
}

/**
 * Thrown by `UsersService.grantRole` when the calling user does not
 * themselves hold a role at least as privileged as the one they're trying
 * to grant (`src/auth/role-privilege.ts`'s `canGrantRole`). Distinct from
 * the endpoint's own `@RequireRole('TENANT_OWNER', 'SECURITY_ADMIN')` gate
 * — that only proves the caller holds *one of those two* roles, not that
 * the specific role being granted is one they're actually entitled to
 * hand out (a `SECURITY_ADMIN` granting themselves `TENANT_OWNER` would
 * otherwise be a real privilege-escalation bug).
 */
export class PrivilegeEscalationError extends Error {
  constructor(
    public readonly targetRole: string,
    public readonly actorRoles: readonly string[],
  ) {
    super(
      `Cannot grant role "${targetRole}": it is more privileged than any role the caller currently holds (${actorRoles.join(', ') || 'none'})`,
    );
    this.name = 'PrivilegeEscalationError';
  }
}

/** Thrown when a role grant/revoke is attempted for a tenant whose Keycloak realm was never provisioned (see docs/human-auth.md's "Known limitation: partial provisioning failure") — role assignment has nowhere to be recorded as the source of truth. */
export class TenantRealmNotProvisionedError extends Error {
  constructor(tenantId: string) {
    super(`Tenant "${tenantId}" has no provisioned Keycloak realm`);
    this.name = 'TenantRealmNotProvisionedError';
  }
}
