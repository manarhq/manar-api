import { describe, expect, it } from 'vitest';
import {
  globMatches,
  matchApprovalRule,
  ruleHasVerifiedCondition,
  type ApprovalRuleLike,
} from './host-approval';

const rule = (r: Partial<ApprovalRuleLike>): ApprovalRuleLike => ({
  id: r.id ?? 'r',
  hostGroupId: r.hostGroupId ?? null,
  hostnamePattern: r.hostnamePattern ?? null,
  cidrs: r.cidrs ?? [],
  requireTpm: r.requireTpm ?? false,
  requireAdcs: r.requireAdcs ?? false,
  adOuDn: r.adOuDn ?? null,
  enabled: r.enabled ?? true,
});
const host = {
  hostGroupId: 'g1',
  hostname: 'DEV-LAPTOP-042',
  ip: '10.4.2.1',
  verified: {
    adcs: true,
    adDn: 'CN=DEV-LAPTOP-042,OU=Laptops,OU=Finance,DC=corp,DC=example',
    tpm: true,
  },
};
const none = { adcs: false, adDn: null, tpm: false };
const verifiedRule = (r: Partial<ApprovalRuleLike> = {}) =>
  rule({ cidrs: ['10.4.0.0/16'], ...r });

describe('matchApprovalRule', () => {
  it('matches nothing when there are no rules', () => {
    expect(matchApprovalRule([], host)).toBeNull();
  });

  it('applies a global rule and a rule for the host group, never another group', () => {
    expect(matchApprovalRule([verifiedRule({ id: 'all' })], host)?.id).toBe(
      'all',
    );
    expect(
      matchApprovalRule([verifiedRule({ id: 'g1', hostGroupId: 'g1' })], host)
        ?.id,
    ).toBe('g1');
    expect(
      matchApprovalRule([verifiedRule({ hostGroupId: 'g2' })], host),
    ).toBeNull();
  });

  it('skips disabled rules', () => {
    expect(
      matchApprovalRule([verifiedRule({ enabled: false })], host),
    ).toBeNull();
  });

  it('matches hostname globs case-insensitively and anchored', () => {
    expect(
      matchApprovalRule(
        [verifiedRule({ hostnamePattern: 'dev-laptop-*' })],
        host,
      ),
    ).not.toBeNull();
    expect(
      matchApprovalRule(
        [verifiedRule({ hostnamePattern: 'DEV-LAPTOP-0??' })],
        host,
      ),
    ).not.toBeNull();
    expect(
      matchApprovalRule([verifiedRule({ hostnamePattern: 'laptop' })], host),
    ).toBeNull();
    expect(
      matchApprovalRule(
        [verifiedRule({ hostnamePattern: 'dev.laptop-*' })],
        host,
      ),
    ).toBeNull();
  });

  it('requires the address inside the rule ranges when set', () => {
    expect(
      matchApprovalRule([rule({ cidrs: ['10.4.0.0/16'] })], host),
    ).not.toBeNull();
    expect(
      matchApprovalRule([rule({ cidrs: ['10.5.0.0/16'] })], host),
    ).toBeNull();
  });

  it('requires an attested TPM key when the rule says so', () => {
    expect(
      matchApprovalRule([rule({ requireTpm: true })], host),
    ).not.toBeNull();
    expect(
      matchApprovalRule([rule({ requireTpm: true })], {
        ...host,
        verified: { ...host.verified, tpm: false },
      }),
    ).toBeNull();
  });

  it('requires a verified AD CS certificate and a verified OU when set', () => {
    expect(
      matchApprovalRule([rule({ requireAdcs: true })], host),
    ).not.toBeNull();
    expect(
      matchApprovalRule([rule({ requireAdcs: true })], {
        ...host,
        verified: none,
      }),
    ).toBeNull();
    const ou = rule({ adOuDn: 'OU=Finance,DC=corp,DC=example' });
    expect(matchApprovalRule([ou], host)).not.toBeNull();
    expect(
      matchApprovalRule(
        [rule({ adOuDn: 'OU=Sales,DC=corp,DC=example' })],
        host,
      ),
    ).toBeNull();
    // AD unreachable: no DN, so an OU rule never matches
    expect(
      matchApprovalRule([ou], {
        ...host,
        verified: { ...host.verified, adDn: null },
      }),
    ).toBeNull();
  });

  it('never matches a rule with only self-reported conditions', () => {
    expect(matchApprovalRule([rule({})], host)).toBeNull();
    expect(
      matchApprovalRule([rule({ hostnamePattern: 'dev-laptop-*' })], host),
    ).toBeNull();
    expect(ruleHasVerifiedCondition(rule({}))).toBe(false);
    expect(ruleHasVerifiedCondition(rule({ hostnamePattern: 'x' }))).toBe(
      false,
    );
    expect(ruleHasVerifiedCondition(rule({ cidrs: ['10.0.0.0/8'] }))).toBe(
      true,
    );
    expect(ruleHasVerifiedCondition(rule({ requireTpm: true }))).toBe(true);
    expect(ruleHasVerifiedCondition(rule({ requireAdcs: true }))).toBe(true);
    expect(ruleHasVerifiedCondition(rule({ adOuDn: 'DC=x' }))).toBe(true);
  });

  it('needs every set condition of a rule, and any one rule', () => {
    const strict = verifiedRule({ id: 'strict', hostnamePattern: 'srv-*' });
    const loose = verifiedRule({ id: 'loose' });
    expect(matchApprovalRule([strict], host)).toBeNull();
    expect(matchApprovalRule([strict, loose], host)?.id).toBe('loose');
  });

  it('matches adversarial globs in linear time', () => {
    const name = 'a'.repeat(5000) + 'b';
    const started = Date.now();
    expect(globMatches('*a*a*a*c', name)).toBe(false);
    expect(Date.now() - started).toBeLessThan(200);
    expect(globMatches('*a*b', name)).toBe(true);
  });
});
