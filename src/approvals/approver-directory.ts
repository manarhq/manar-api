import { Injectable } from '@nestjs/common';
import { ControlPrismaService } from '../database/control-prisma.service';
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

/**
 * Who may approve in a workspace, read from the current state each time (never from role
 * bindings that were synced at the person's last sign-in, which go stale when an approver is
 * removed). When the identity track's `memberships` table exists it is authoritative: an ACTIVE
 * membership of this tenant whose role or extra roles include an approver role. Only installs
 * without that table fall back to the tenant's role bindings.
 */
@Injectable()
export class ApproverDirectory {
  private hasMemberships: boolean | null = null;

  constructor(private readonly control: ControlPrismaService) {}

  private async memberships(): Promise<boolean> {
    if (this.hasMemberships) return true;
    const r = await this.control.$queryRaw<
      { t: string | null }[]
    >`SELECT to_regclass('public.memberships')::text AS t`;
    this.hasMemberships = r[0]?.t != null;
    return this.hasMemberships;
  }

  async listSubjects(
    tenantId: string,
    tenantClient: Pick<TenantPrismaClient, 'roleBinding'>,
  ): Promise<string[]> {
    if (!(await this.memberships())) return listApproverSubjects(tenantClient);
    const roles = [...APPROVER_ROLES];
    const rows = await this.control.$queryRaw<{ subject: string }[]>`
      SELECT DISTINCT "subject" FROM "memberships"
      WHERE "tenantId" = ${tenantId} AND "status"::text = 'ACTIVE'
        AND ("role"::text = ANY(${roles}) OR "extraRoles"::text[] && ${roles})`;
    return rows.map((r) => r.subject);
  }

  /** Fail closed: no subject, or any lookup failure, is "no". */
  async canApprove(
    tenantId: string,
    tenantClient: Pick<TenantPrismaClient, 'roleBinding'>,
    subject: string | null | undefined,
  ): Promise<boolean> {
    if (!subject) return false;
    try {
      if (!(await this.memberships())) return canApprove(tenantClient, subject);
      return (await this.listSubjects(tenantId, tenantClient)).includes(
        subject,
      );
    } catch {
      return false;
    }
  }
}
