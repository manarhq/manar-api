/**
 * The eight application roles (Section 11 of the master prompt): Tenant
 * Owner, Security Admin, AI Governance Manager, SOC Operator, Approver,
 * Auditor, Developer, Read Only.
 *
 * Single source of truth for the role name convention (`SCREAMING_SNAKE_CASE`)
 * used identically in three places that must never drift apart:
 *   1. Keycloak realm roles seeded by `TenantProvisioningService` for every
 *      tenant realm (`src/keycloak/tenant-provisioning.service.ts`).
 *   2. The `Role` enum in `prisma/tenant.prisma` (`RoleBinding.role`).
 *   3. `@RequireRole(...)` arguments checked by `RolesGuard`.
 *
 * A JWT's `realm_access.roles` claim and a tenant DB `RoleBinding.role` row
 * are expected to use these exact strings — no translation layer between
 * "Keycloak's role name" and "Manar's role name".
 */
export const ROLES = [
  'TENANT_OWNER',
  'SECURITY_ADMIN',
  'AI_GOVERNANCE_MANAGER',
  'SOC_OPERATOR',
  'APPROVER',
  'AUDITOR',
  'DEVELOPER',
  'READ_ONLY',
] as const;

export type RoleName = (typeof ROLES)[number];

export function isRoleName(value: string): value is RoleName {
  return (ROLES as readonly string[]).includes(value);
}
