import { describe, expect, it } from 'vitest';

import { PolicyEffectSchema, PolicyRuleSchema } from './policy-content.schema';

/**
 * Phase 1 vocabulary change: `CLAUDE.md` §7 mandates `APPROVAL_REQUIRED`.
 * `REQUIRE_APPROVAL` was the identifier this codebase used until now and is
 * still present in `PolicyVersion.content` rows written before the change.
 * Those rows are immutable and carry a `contentHash`, so they cannot be
 * rewritten — they have to keep parsing.
 */
describe('PolicyEffectSchema', () => {
  it('accepts the CLAUDE.md §7 vocabulary', () => {
    expect(PolicyEffectSchema.parse('ALLOW')).toBe('ALLOW');
    expect(PolicyEffectSchema.parse('DENY')).toBe('DENY');
    expect(PolicyEffectSchema.parse('APPROVAL_REQUIRED')).toBe(
      'APPROVAL_REQUIRED',
    );
  });

  it('normalises the deprecated REQUIRE_APPROVAL alias on read', () => {
    expect(PolicyEffectSchema.parse('REQUIRE_APPROVAL')).toBe(
      'APPROVAL_REQUIRED',
    );
  });

  it('rejects anything else, so a typo cannot become a silent ALLOW', () => {
    for (const bad of [
      'approval_required',
      'REQUIRES_APPROVAL',
      'PERMIT',
      '',
      'APPROVE',
    ]) {
      expect(() => PolicyEffectSchema.parse(bad)).toThrow();
    }
  });

  it('normalises the alias when it arrives nested inside a rule', () => {
    const rule = PolicyRuleSchema.parse({
      name: 'legacy rule',
      toolId: 'demo-iam',
      actionId: 'disable-user',
      resourcePattern: '*',
      effect: 'REQUIRE_APPROVAL',
    });

    expect(rule.effect).toBe('APPROVAL_REQUIRED');
  });
});
