import { describe, expect, it } from 'vitest';
import { ROLES } from './roles';
import {
  canGrantRole,
  privilegeRank,
  ROLE_PRIVILEGE_ORDER,
} from './role-privilege';

describe('role-privilege', () => {
  it('ROLE_PRIVILEGE_ORDER contains every ROLES entry exactly once', () => {
    expect([...ROLE_PRIVILEGE_ORDER].sort()).toEqual([...ROLES].sort());
    expect(new Set(ROLE_PRIVILEGE_ORDER).size).toBe(
      ROLE_PRIVILEGE_ORDER.length,
    );
  });

  it('TENANT_OWNER is the most privileged (rank 0) and READ_ONLY the least', () => {
    expect(privilegeRank('TENANT_OWNER')).toBe(0);
    expect(privilegeRank('READ_ONLY')).toBe(ROLES.length - 1);
  });

  describe('canGrantRole', () => {
    it('a SECURITY_ADMIN cannot grant TENANT_OWNER, even to themselves', () => {
      expect(canGrantRole(['SECURITY_ADMIN'], 'TENANT_OWNER')).toBe(false);
    });

    it('a SECURITY_ADMIN can grant SECURITY_ADMIN or any less-privileged role', () => {
      expect(canGrantRole(['SECURITY_ADMIN'], 'SECURITY_ADMIN')).toBe(true);
      expect(canGrantRole(['SECURITY_ADMIN'], 'AI_GOVERNANCE_MANAGER')).toBe(
        true,
      );
      expect(canGrantRole(['SECURITY_ADMIN'], 'READ_ONLY')).toBe(true);
    });

    it('a TENANT_OWNER can grant any of the eight roles, including TENANT_OWNER', () => {
      for (const role of ROLES) {
        expect(canGrantRole(['TENANT_OWNER'], role)).toBe(true);
      }
    });

    it('a READ_ONLY-only actor cannot grant anything more privileged than READ_ONLY', () => {
      expect(canGrantRole(['READ_ONLY'], 'READ_ONLY')).toBe(true);
      expect(canGrantRole(['READ_ONLY'], 'DEVELOPER')).toBe(false);
      expect(canGrantRole(['READ_ONLY'], 'TENANT_OWNER')).toBe(false);
    });

    it('holding multiple roles uses the most-privileged one', () => {
      expect(
        canGrantRole(['READ_ONLY', 'SECURITY_ADMIN'], 'AI_GOVERNANCE_MANAGER'),
      ).toBe(true);
      expect(
        canGrantRole(['READ_ONLY', 'SECURITY_ADMIN'], 'TENANT_OWNER'),
      ).toBe(false);
    });

    it('an actor holding no roles at all can grant nothing', () => {
      expect(canGrantRole([], 'READ_ONLY')).toBe(false);
    });
  });
});
