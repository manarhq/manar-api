import { describe, expect, it } from 'vitest';
import {
  AGENT_HIGH_RISK_SCORE,
  decisionRights,
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
    // A personal workspace has nobody else to ask.
    expect(
      decisionRights({
        ...base,
        admin: true,
        owner: true,
        sensitive: 'high_risk',
        company: false,
      }).choices,
    ).toContain('approve_once');
  });

  it('anyone else decides nothing', () => {
    expect(decisionRights(base)).toMatchObject({
      choices: [],
      canRevoke: false,
    });
  });
});
