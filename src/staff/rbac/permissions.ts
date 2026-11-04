/**
 * Staff permission catalogue and built-in staff roles (DESK spec §10.3, founder answers of 4 Nov).
 * Permissions are fixed keys in code, never created at runtime. Each key is one relation on
 * `platform:manar` in src/authorization/model/manar.fga (dots become underscores).
 *
 * Founder override (4 Nov 09:30): PII is masked for every staff role until a logged reveal, so the
 * spec's `people.view_pii` does not exist; `people.reveal_pii` is held by every built-in role that
 * works with customers (everyone except Auditor).
 */
export const STAFF_PERMISSIONS = [
  'people.search',
  'orgs.search',
  'people.view',
  'orgs.view',
  'people.reveal_pii',
  'people.sessions.revoke',
  'notes.write',
  'tags.write',
  'restrict.warn',
  'restrict.suspend.propose',
  'restrict.suspend',
  'restrict.lift',
  'restrict.ban',
  'restrict.unban.propose',
  'restrict.unban.approve',
  'restrict.immediate.approve',
  'appeals.review',
  'matches.review',
  'staff.view',
  'staff.manage',
  'staff.owner.grant.propose',
  'staff.owner.grant.approve',
  'staff.roles.manage',
  'staff.audit.view',
  'errors.view',
] as const;

export type StaffPermission = (typeof STAFF_PERMISSIONS)[number];

export function isStaffPermission(v: unknown): v is StaffPermission {
  return (STAFF_PERMISSIONS as readonly unknown[]).includes(v);
}

/** AC-31: these never go into a custom role. */
export const OWNER_ONLY: ReadonlySet<StaffPermission> = new Set([
  'restrict.ban',
  'restrict.unban.approve',
  'staff.owner.grant.approve',
]);

export const BUILT_IN_ROLE_KEYS = [
  'owner',
  'admin',
  'trust_safety',
  'support',
  'billing',
  'dev',
  'sales',
  'partnerships',
  'auditor',
] as const;
export type BuiltInStaffRole = (typeof BUILT_IN_ROLE_KEYS)[number];

const LOOK = [
  'people.search',
  'orgs.search',
  'people.view',
  'orgs.view',
] as const;

export const BUILT_IN_ROLES: Record<
  BuiltInStaffRole,
  readonly StaffPermission[]
> = {
  owner: STAFF_PERMISSIONS,
  admin: [
    ...LOOK,
    'people.reveal_pii',
    'people.sessions.revoke',
    'notes.write',
    'tags.write',
    'restrict.warn',
    'restrict.suspend',
    'restrict.lift',
    'restrict.immediate.approve',
    'appeals.review',
    'matches.review',
    'staff.view',
    'staff.manage',
    'staff.roles.manage',
    'staff.owner.grant.propose',
    'staff.audit.view',
    'errors.view',
  ],
  trust_safety: [
    ...LOOK,
    'people.reveal_pii',
    'people.sessions.revoke',
    'notes.write',
    'tags.write',
    'restrict.warn',
    'restrict.suspend.propose',
    'appeals.review',
    'matches.review',
    'errors.view',
  ],
  support: [
    ...LOOK,
    'people.reveal_pii',
    'people.sessions.revoke',
    'notes.write',
    'tags.write',
    'errors.view',
  ],
  billing: [
    ...LOOK,
    'people.reveal_pii',
    'notes.write',
    'tags.write',
    'errors.view',
  ],
  dev: [...LOOK, 'people.reveal_pii', 'notes.write', 'errors.view'],
  sales: [...LOOK, 'people.reveal_pii', 'notes.write', 'tags.write'],
  partnerships: [...LOOK, 'people.reveal_pii', 'notes.write', 'tags.write'],
  auditor: [...LOOK, 'staff.view', 'staff.audit.view', 'errors.view'],
};

export const BUILT_IN_ROLE_NAMES: Record<BuiltInStaffRole, string> = {
  owner: 'Owner',
  admin: 'Admin',
  trust_safety: 'Trust & Safety',
  support: 'Support',
  billing: 'Billing',
  dev: 'Dev',
  sales: 'Sales',
  partnerships: 'Partnerships',
  auditor: 'Auditor',
};

export const PLATFORM_OBJECT = 'platform:manar';

export function fgaRelation(p: StaffPermission): string {
  return p.replaceAll('.', '_');
}

/** One OpenFGA object per (role, scope); Phase 1 has the platform scope only. */
export function roleObject(roleId: string): string {
  return `role:${roleId}~platform~manar`;
}
