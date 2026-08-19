import { ROLES, RoleName } from './roles';

/**
 * Phase 14 (Users/Roles/Settings) — a real, total privilege ordering over
 * the eight fixed roles (`src/auth/roles.ts`), most-privileged first. This
 * is what `UsersService.grantRole` enforces the privilege-escalation guard
 * against: a caller must never be able to grant a role more privileged
 * than any role they themselves currently hold (Section 11's role model
 * has no notion of "grant only what you were explicitly delegated" —
 * every `SECURITY_ADMIN`/`TENANT_OWNER` can manage role bindings at all,
 * per `RequireRole('TENANT_OWNER', 'SECURITY_ADMIN')` on the grant/revoke
 * endpoints — so without this check, any `SECURITY_ADMIN` could simply
 * grant themselves `TENANT_OWNER` and every other role, which would make
 * the two-role gate meaningless).
 *
 * The ordering itself is a genuine judgment call — the eight roles aren't
 * a strict capability lattice in the codebase's data model (there's no
 * `RolePermissions` table to derive one from mechanically) — but it
 * reflects each role's actual scope per Section 11's role catalog:
 *
 *   - `TENANT_OWNER` — the tenant's ultimate administrator; the only role
 *     that should ever be able to grant `TENANT_OWNER` itself.
 *   - `SECURITY_ADMIN` — manages security posture tenant-wide (policies,
 *     kill switches, users/roles below `TENANT_OWNER`) but doesn't own
 *     the tenant relationship itself.
 *   - `AI_GOVERNANCE_MANAGER` — governs the AI advisory/DLP surface
 *     specifically, a narrower slice of `SECURITY_ADMIN`'s scope.
 *   - `SOC_OPERATOR` — day-to-day security-operations user (tasks,
 *     agents, monitoring) without governance authority.
 *   - `APPROVER` — can decide pending approvals, a single, specific
 *     capability rather than broad operational access.
 *   - `AUDITOR` — read-oriented oversight (audit/evidence) with no
 *     mutating capability at all.
 *   - `DEVELOPER` — builds/registers tools and integrations; scoped to
 *     the tool-development surface.
 *   - `READ_ONLY` — the floor: view-only, no mutating capability
 *     anywhere.
 *
 * A dev-time invariant check below guarantees this list can never
 * silently drift out of sync with `ROLES` (e.g. a ninth role added to
 * `ROLES` but forgotten here) — the privilege-escalation guard would
 * otherwise fail *open* for whatever role fell through the gap, which is
 * exactly the kind of security property this file exists to protect.
 */
export const ROLE_PRIVILEGE_ORDER: readonly RoleName[] = [
  'TENANT_OWNER',
  'SECURITY_ADMIN',
  'AI_GOVERNANCE_MANAGER',
  'SOC_OPERATOR',
  'APPROVER',
  'AUDITOR',
  'DEVELOPER',
  'READ_ONLY',
];

(function assertPrivilegeOrderMatchesRoles(): void {
  const orderedSet = new Set(ROLE_PRIVILEGE_ORDER);
  const rolesSet = new Set(ROLES);
  const missing = ROLES.filter((role) => !orderedSet.has(role));
  const extra = ROLE_PRIVILEGE_ORDER.filter((role) => !rolesSet.has(role));
  if (missing.length > 0 || extra.length > 0) {
    throw new Error(
      `ROLE_PRIVILEGE_ORDER has drifted out of sync with ROLES (missing: [${missing.join(', ')}], extra: [${extra.join(', ')}]) — every role in ROLES must appear in ROLE_PRIVILEGE_ORDER exactly once, or the privilege-escalation guard could silently fail open for the missing role`,
    );
  }
})();

/** Lower rank == more privileged. `TENANT_OWNER` is rank 0, `READ_ONLY` is rank 7. */
export function privilegeRank(role: RoleName): number {
  return ROLE_PRIVILEGE_ORDER.indexOf(role);
}

/** The most-privileged rank among `roles` (the lowest number), or `undefined` if `roles` is empty (a user with no roles at all can grant nothing). */
export function highestPrivilegeRank(
  roles: readonly RoleName[],
): number | undefined {
  if (roles.length === 0) return undefined;
  return Math.min(...roles.map(privilegeRank));
}

/**
 * The privilege-escalation guard itself: `actorRoles` may grant
 * `targetRole` only if at least one role the actor already holds is at
 * least as privileged as `targetRole` (i.e. the actor's best rank is
 * numerically `<=` the target's rank — remember lower is more
 * privileged). A `SECURITY_ADMIN` (rank 1) can grant `SECURITY_ADMIN` or
 * anything less privileged, but not `TENANT_OWNER` (rank 0) — including
 * to themselves. A `TENANT_OWNER` (rank 0, the minimum possible) can
 * always grant any role, since no role has a lower rank to be blocked by.
 * An actor holding no roles at all can grant nothing.
 */
export function canGrantRole(
  actorRoles: readonly RoleName[],
  targetRole: RoleName,
): boolean {
  const bestActorRank = highestPrivilegeRank(actorRoles);
  if (bestActorRank === undefined) return false;
  return bestActorRank <= privilegeRank(targetRole);
}
