import { describe, expect, it } from 'vitest';
import {
  AGENT_HIGH_RISK_SCORE,
  STEP_UP_MAX_AGE_SECONDS,
  decisionRights,
  freshSignIn,
  sensitiveReason,
} from './decision-rights';

const base = {
  admin: false,
  owner: false,
  adminsOnly: false,
  company: true,
  sensitive: null,
  actionId: 'shell',
} as const;

describe('decision rights', () => {
  it('sensitive: high risk from the threshold, or a handover by id or name', () => {
    expect(
      sensitiveReason({ actionId: 'x', riskScore: AGENT_HIGH_RISK_SCORE - 1 }),
    ).toBeNull();
    expect(
      sensitiveReason({ actionId: 'x', riskScore: AGENT_HIGH_RISK_SCORE }),
    ).toBe('high_risk');
    expect(sensitiveReason({ actionId: 'x', highRisk: true })).toBe(
      'high_risk',
    );
    expect(
      sensitiveReason({ actionId: 'uuid-1', actionName: 'entra.user.create' }),
    ).toBe('handover');
    expect(sensitiveReason({ actionId: 'secret.use', highRisk: true })).toBe(
      'handover',
    );
  });

  it('an owner answers routine requests only, once or deny', () => {
    expect(decisionRights({ ...base, owner: true }).choices).toEqual([
      'approve_once',
      'deny',
    ]);
    expect(
      decisionRights({ ...base, owner: true, sensitive: 'handover' }),
    ).toMatchObject({
      choices: ['deny'],
      needs: 'needs_admin',
      why: 'handover',
    });
    expect(
      decisionRights({ ...base, owner: true, adminsOnly: true }),
    ).toMatchObject({
      choices: [],
      needs: 'admins_only',
      canRevoke: false,
    });
  });

  it('an approver decides anything except their own sensitive request in a company workspace', () => {
    expect(decisionRights({ ...base, admin: true }).choices).toContain(
      'approve_8h',
    );
    expect(
      decisionRights({
        ...base,
        admin: true,
        owner: true,
        sensitive: 'high_risk',
      }),
    ).toMatchObject({
      choices: ['deny'],
      needs: 'needs_another_admin',
    });
    // A personal workspace has nobody else to ask: once or 8 hours, never always, after a fresh
    // sign-in (founder decision, 4 Nov 2026; passkeys replace the fresh sign-in in Phase A).
    expect(
      decisionRights({
        ...base,
        admin: true,
        owner: true,
        sensitive: 'high_risk',
        company: false,
      }),
    ).toMatchObject({
      choices: ['approve_once', 'approve_8h', 'deny'],
      stepUp: true,
      why: 'high_risk',
    });
    expect(
      decisionRights({ ...base, admin: true, company: false }).stepUp,
    ).toBe(false);
  });

  it('a personal workspace owner never self-grants "always": make a rule instead', () => {
    const site = { ...base, actionId: 'site.connect', company: false };
    expect(
      decisionRights({ ...site, admin: true, owner: true }).choices,
    ).toEqual(['approve_once', 'approve_8h', 'deny']);
    // A device with no recorded owner is still the only person's own device.
    expect(
      decisionRights({ ...site, admin: true, owner: false }).choices,
    ).not.toContain('approve_always');
    expect(
      decisionRights({
        ...base,
        admin: true,
        owner: false,
        company: false,
        sensitive: 'handover',
      }),
    ).toMatchObject({ stepUp: true });
    // A company approver may still remember a site for someone else's device.
    expect(
      decisionRights({ ...base, actionId: 'site.connect', admin: true })
        .choices,
    ).toContain('approve_always');
  });

  it('anyone else decides nothing', () => {
    expect(decisionRights(base)).toMatchObject({
      choices: [],
      canRevoke: false,
    });
  });

  it('a fresh sign-in is at most STEP_UP_MAX_AGE_SECONDS old; unknown is stale', () => {
    const now = 1_800_000_000_000;
    expect(freshSignIn(now / 1000 - STEP_UP_MAX_AGE_SECONDS, now)).toBe(true);
    expect(freshSignIn(now / 1000 - STEP_UP_MAX_AGE_SECONDS - 1, now)).toBe(
      false,
    );
    expect(freshSignIn(undefined, now)).toBe(false);
  });
});
