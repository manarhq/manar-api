import { describe, expect, it } from 'vitest';
import { matchApprovalRule, type ApprovalRuleLike } from './host-approval';

const rule = (r: Partial<ApprovalRuleLike>): ApprovalRuleLike => ({
  id: r.id ?? 'r',
  hostGroupId: r.hostGroupId ?? null,
  hostnamePattern: r.hostnamePattern ?? null,
  cidrs: r.cidrs ?? [],
  requireTpm: r.requireTpm ?? false,
  enabled: r.enabled ?? true,
});
const host = {
  hostGroupId: 'g1',
  hostname: 'DEV-LAPTOP-042',
  ip: '10.4.2.1',
  keyType: 'TPM' as const,
};

describe('matchApprovalRule', () => {
  it('matches nothing when there are no rules', () => {
    expect(matchApprovalRule([], host)).toBeNull();
  });

  it('applies a global rule and a rule for the host group, never another group', () => {
    expect(matchApprovalRule([rule({ id: 'all' })], host)?.id).toBe('all');
    expect(
      matchApprovalRule([rule({ id: 'g1', hostGroupId: 'g1' })], host)?.id,
    ).toBe('g1');
    expect(matchApprovalRule([rule({ hostGroupId: 'g2' })], host)).toBeNull();
  });

  it('skips disabled rules', () => {
    expect(matchApprovalRule([rule({ enabled: false })], host)).toBeNull();
  });

  it('matches hostname globs case-insensitively and anchored', () => {
    expect(
      matchApprovalRule([rule({ hostnamePattern: 'dev-laptop-*' })], host),
    ).not.toBeNull();
    expect(
      matchApprovalRule([rule({ hostnamePattern: 'DEV-LAPTOP-0??' })], host),
    ).not.toBeNull();
    expect(
      matchApprovalRule([rule({ hostnamePattern: 'laptop' })], host),
    ).toBeNull();
    expect(
      matchApprovalRule([rule({ hostnamePattern: 'dev.laptop-*' })], host),
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

  it('requires a TPM-backed key when the rule says so', () => {
    expect(
      matchApprovalRule([rule({ requireTpm: true })], host),
    ).not.toBeNull();
    expect(
      matchApprovalRule([rule({ requireTpm: true })], {
        ...host,
        keyType: 'SOFTWARE',
      }),
    ).toBeNull();
  });

  it('needs every set condition of a rule, and any one rule', () => {
    const strict = rule({
      id: 'strict',
      hostnamePattern: 'srv-*',
      cidrs: ['10.4.0.0/16'],
    });
    const loose = rule({ id: 'loose', cidrs: ['10.4.0.0/16'] });
    expect(matchApprovalRule([strict], host)).toBeNull();
    expect(matchApprovalRule([strict, loose], host)?.id).toBe('loose');
  });
});
