import {
  BUILT_IN_ROLE_KEYS,
  type BuiltInStaffRole,
} from '../../staff/rbac/permissions';

export interface SeedOptions {
  email?: string;
  name?: string;
  role?: string;
  eligible?: string;
  team?: string;
  title?: string;
}

const TEAMS = [
  'DEV',
  'SALES',
  'PARTNERSHIPS',
  'SUPPORT',
  'BILLING',
  'TRUST_SAFETY',
  'LEADERSHIP',
];

export const isBuiltInRole = (v: string): v is BuiltInStaffRole =>
  (BUILT_IN_ROLE_KEYS as readonly string[]).includes(v);
export const isStaffTeam = (v: string) => TEAMS.includes(v);
