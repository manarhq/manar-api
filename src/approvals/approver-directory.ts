import { Injectable } from '@nestjs/common';
import { SITE_CONNECT_ACTION } from '../jail/jail-sites';
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

/** `admin`: an approver role. `owner`: the device's owner or the agent's creator. */
export type DeciderKind = 'admin' | 'owner';

/**
 * What a decider may choose. An owner answers once or denies; standing permissions (8 hours,
 * always) and rules are an admin's call. `approve_always` exists for a new site only.
 */
export function choicesFor(
  kind: DeciderKind | null,
  approval: { actionId: string },
): ('approve_once' | 'approve_8h' | 'approve_always' | 'deny')[] {
  if (!kind) return [];
  if (kind === 'owner') return ['approve_once', 'deny'];
  return approval.actionId === SITE_CONNECT_ACTION
    ? ['approve_once', 'approve_8h', 'approve_always', 'deny']
    : ['approve_once', 'approve_8h', 'deny'];
}

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

  /**
   * "Admins only" (founder decision, 3 Nov 2026): a company workspace can stop device owners from
   * deciding their own approvals. Fail closed: a failed read is "admins only".
   */
  async adminsOnly(tenantId: string): Promise<boolean> {
    try {
      const t = await this.control.tenant.findUnique({
        where: { id: tenantId },
        select: { kind: true, approvalsAdminsOnly: true },
      });
      if (!t) return true;
      return t.kind === 'COMPANY' && t.approvalsAdminsOnly;
    } catch {
      return true;
    }
  }

  /**
   * Who may decide one approval (founder decision, 3 Nov 2026): an approver role decides anything
   * (`admin`); the person who owns the device, or who created the agent, decides that device's or
   * agent's own requests (`owner`), unless the workspace is "admins only". Null: may not decide.
   * `ownerSubject` is the device's `ownerSubject` or the agent creator's Keycloak subject.
   */
  async deciderKind(
    tenantId: string,
    tenantClient: Pick<TenantPrismaClient, 'roleBinding'>,
    subject: string | null | undefined,
    ownerSubject: string | null | undefined,
  ): Promise<DeciderKind | null> {
    if (!subject) return null;
    if (await this.canApprove(tenantId, tenantClient, subject)) return 'admin';
    if (!ownerSubject || ownerSubject !== subject) return null;
    return (await this.adminsOnly(tenantId)) ? null : 'owner';
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
