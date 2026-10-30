import { ForbiddenException, Injectable } from '@nestjs/common';
import { failClosed } from '../common/fail-closed/fail-closed';
import { ControlPrismaService } from '../database/control-prisma.service';
import { privilegeRank } from './role-privilege';
import { isRoleName, ROLES, type RoleName } from './roles';

export type WorkspaceKind = 'PERSONAL' | 'COMPANY' | 'SAMPLE';

export interface ResolvedWorkspace {
  tenantId: string;
  tenantSlug: string;
  kind: WorkspaceKind;
  membershipId: string;
  roles: RoleName[];
}

/** Every role a workspace owner holds (the 8 roles are flat checks in `RolesGuard`). */
export function ownerRoles(): { role: RoleName; extraRoles: RoleName[] } {
  return {
    role: 'TENANT_OWNER',
    extraRoles: ROLES.filter((r) => r !== 'TENANT_OWNER'),
  };
}

/** Splits a role set into the stored (primary, extras) pair; primary is the most privileged. */
export function splitRoles(roles: readonly RoleName[]): {
  role: RoleName;
  extraRoles: RoleName[];
} | null {
  const unique = [...new Set(roles)].sort(
    (a, b) => privilegeRank(a) - privilegeRank(b),
  );
  const [role, ...extraRoles] = unique;
  return role ? { role, extraRoles } : null;
}

export function rolesOf(m: {
  role: string;
  extraRoles: readonly string[];
}): RoleName[] {
  return [...new Set([m.role, ...m.extraRoles])].filter(isRoleName);
}

/**
 * The only place that turns (who, which workspace) into roles. Access needs an ACTIVE Membership
 * for an ACTIVE tenant. The workspace named by the caller is a request, never a grant; anything
 * that does not resolve is a 403 (a control-DB failure is a 503, see `failClosed`).
 */
@Injectable()
export class MembershipService {
  constructor(private readonly control: ControlPrismaService) {}

  async resolveActive(input: {
    subject: string;
    requestedTenantId?: string;
    boundTenantId?: string;
  }): Promise<ResolvedWorkspace> {
    const { subject, requestedTenantId, boundTenantId } = input;
    // A legacy per-tenant realm only ever reaches its own tenant.
    if (
      boundTenantId &&
      requestedTenantId &&
      requestedTenantId !== boundTenantId
    ) {
      throw new ForbiddenException('Workspace not available');
    }
    const wanted = requestedTenantId ?? boundTenantId;

    const rows = await failClosed('control-db', () =>
      this.control.membership.findMany({
        where: {
          subject,
          status: 'ACTIVE',
          ...(wanted ? { tenantId: wanted } : {}),
          tenant: { status: 'ACTIVE' },
        },
        include: { tenant: true },
        orderBy: { createdAt: 'asc' },
      }),
    );
    // No selection: the personal workspace first, otherwise the oldest membership. A SAMPLE
    // workspace is never a default: it is reached only by choosing it.
    const m = wanted
      ? rows[0]
      : (rows.find((r) => r.tenant.kind === 'PERSONAL') ??
        rows.find((r) => r.tenant.kind !== 'SAMPLE'));
    if (!m) throw new ForbiddenException('Workspace not available');
    return {
      tenantId: m.tenantId,
      tenantSlug: m.tenant.slug,
      kind: m.tenant.kind,
      membershipId: m.id,
      roles: rolesOf(m),
    };
  }

  /** Workspaces (any membership status but REMOVED) for the switcher and the setup screen. */
  listForSubject(subject: string) {
    return failClosed('control-db', () =>
      this.control.membership.findMany({
        where: { subject, status: { in: ['ACTIVE', 'PENDING'] } },
        include: { tenant: true },
        orderBy: { createdAt: 'asc' },
      }),
    );
  }
}
