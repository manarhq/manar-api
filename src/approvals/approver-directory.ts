import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';

/**
 * Roles that may decide an approval (the same three `ApprovalsController` requires). A personal
 * workspace's owner is its TENANT_OWNER. The identity track's Membership table replaces these two
 * reads; nothing else in the approvals track knows how roles are stored.
 */
export const APPROVER_ROLES = [
  'TENANT_OWNER',
  'SECURITY_ADMIN',
  'APPROVER',
] as const;

export async function listApproverSubjects(
  client: Pick<TenantPrismaClient, 'roleBinding'>,
): Promise<string[]> {
  const rows = await client.roleBinding.findMany({
    where: { role: { in: [...APPROVER_ROLES] } },
    select: { user: { select: { keycloakSubject: true } } },
  });
  return [...new Set(rows.map((r) => r.user.keycloakSubject))];
}

/** Fail closed: no subject (an older host without an owner) can never approve. */
export async function canApprove(
  client: Pick<TenantPrismaClient, 'roleBinding'>,
  subject: string | null | undefined,
): Promise<boolean> {
  if (!subject) return false;
  const hit = await client.roleBinding.findFirst({
    where: {
      role: { in: [...APPROVER_ROLES] },
      user: { keycloakSubject: subject },
    },
    select: { id: true },
  });
  return hit !== null;
}
