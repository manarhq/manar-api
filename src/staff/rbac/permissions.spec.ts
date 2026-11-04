import { readFileSync } from 'node:fs';
import {
  BUILT_IN_ROLES,
  OWNER_ONLY,
  STAFF_PERMISSIONS,
  fgaRelation,
  roleObject,
} from './permissions';

describe('staff permission catalogue', () => {
  const dsl = readFileSync('src/authorization/model/manar.fga', 'utf8');
  const platform = dsl.slice(dsl.indexOf('type platform'));

  it('every built-in role holds only catalogue keys', () => {
    for (const perms of Object.values(BUILT_IN_ROLES))
      for (const p of perms) expect(STAFF_PERMISSIONS).toContain(p);
  });

  it('Owner holds everything; Owner-only keys are in no other built-in role', () => {
    expect([...BUILT_IN_ROLES.owner].sort()).toEqual(
      [...STAFF_PERMISSIONS].sort(),
    );
    for (const [role, perms] of Object.entries(BUILT_IN_ROLES)) {
      if (role === 'owner') continue;
      for (const p of perms) expect(OWNER_ONLY.has(p)).toBe(false);
    }
  });

  it('Auditor has no action and no reveal (founder: masked for every role until a reveal)', () => {
    for (const p of BUILT_IN_ROLES.auditor) expect(p).toMatch(/search$|view$/);
    for (const role of [
      'admin',
      'support',
      'dev',
      'sales',
      'trust_safety',
    ] as const)
      expect(BUILT_IN_ROLES[role]).toContain('people.reveal_pii');
  });

  it('Admin can suspend but not ban; Trust & Safety only proposes a suspend', () => {
    expect(BUILT_IN_ROLES.admin).toContain('restrict.suspend');
    expect(BUILT_IN_ROLES.admin).not.toContain('restrict.ban');
    expect(BUILT_IN_ROLES.trust_safety).toContain('restrict.suspend.propose');
    expect(BUILT_IN_ROLES.trust_safety).not.toContain('restrict.suspend');
  });

  it('every permission is a relation on platform in manar.fga', () => {
    for (const p of STAFF_PERMISSIONS)
      expect(platform).toContain(`define ${fgaRelation(p)}: [role#assignee]`);
  });

  it('names relations and role objects deterministically', () => {
    expect(fgaRelation('people.reveal_pii')).toBe('people_reveal_pii');
    expect(roleObject('r1')).toBe('role:r1~platform~manar');
  });
});
