import { describe, expect, it } from 'vitest';
import { computeParameterHash } from '../approvals/parameter-hash.util';
import { EnforcementDependencyUnavailableException } from '../common/fail-closed/fail-closed';
import { makeDecisionHarness } from './decision-pipeline.fakes';

/**
 * S6/F7 (spec §6.2): redeeming a single-use approval grant re-runs the whole
 * decision against current state (kill switches at every level, AI-system
 * state, task scope and TTL, OpenFGA, current policy) and records it as a
 * `Decision` (ADR-003). Only a change to DENY refuses: the approval already
 * covers APPROVAL_REQUIRED.
 */

const REQUEST = {
  taskId: 'task-1',
  toolId: 'edr',
  actionId: 'isolate-host',
  resource: 'host-1',
};
const PARAMS = { reason: 'ransomware', nested: { b: 2, a: 1 } };

describe('AuthorizationService.authorizeRedemption re-runs the decision at grant redemption (S6/F7)', () => {
  const VALID_GRANT = { valid: true as const, grantId: 'grant-1' };
  const redeem = (
    h: ReturnType<typeof makeDecisionHarness>,
    grant: typeof VALID_GRANT | { valid: false; reason: string } = VALID_GRANT,
  ) =>
    h.service.authorizeRedemption(
      h.tenantClient,
      'tenant-1',
      'agent-1',
      REQUEST,
      { channel: 'REST', params: PARAMS },
      grant,
    );

  it('still allowed: ALLOW recorded with the grant id, grant consumed in the same transaction, no second execution count', async () => {
    const h = makeDecisionHarness();

    const result = await redeem(h);

    expect(result).toMatchObject({
      decision: 'ALLOW',
      decisionId: 'decision-1',
    });
    expect(h.decisions[0]).toMatchObject({
      outcome: 'ALLOW',
      stage: 'GRANT_REDEMPTION',
      grantId: 'grant-1',
      inputsHash: computeParameterHash({ ...REQUEST, params: PARAMS }),
    });
    expect(h.events).toEqual(['consume:tx', 'decision:tx']);
    expect(h.client.authorizationGrant.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          id: 'grant-1',
          consumedAt: null,
          revokedAt: null,
        }) as unknown,
      }),
    );
    // The human approved this risk; it is not re-gated on the score.
    expect(h.riskScore).not.toHaveBeenCalled();
  });

  it('the policy still asking for approval does not block: the approval satisfied it', async () => {
    const h = makeDecisionHarness({
      policy: {
        effect: 'APPROVAL_REQUIRED',
        policyId: 'policy-1',
        policyVersionId: 'policy-version-2',
      },
    });

    await expect(redeem(h)).resolves.toMatchObject({ decision: 'ALLOW' });
    expect(h.decisions[0]).toMatchObject({
      policyVersionId: 'policy-version-2',
    });
  });

  it('policy republished to DENY after approval: refused, DENY recorded, grant left unconsumed', async () => {
    const h = makeDecisionHarness({
      policy: {
        effect: 'DENY',
        policyId: 'policy-1',
        policyVersionId: 'policy-version-3',
      },
    });

    const result = await redeem(h);

    expect(result).toMatchObject({ decision: 'DENY', reason: 'policy_denied' });
    expect(h.decisions[0]).toMatchObject({
      outcome: 'DENY',
      stage: 'GRANT_REDEMPTION',
      grantId: 'grant-1',
      reasonCodes: ['policy_denied'],
      policyVersionId: 'policy-version-3',
    });
    expect(h.client.authorizationGrant.updateMany).not.toHaveBeenCalled();
  });

  it.each([
    'platform_kill_switch_active',
    'tenant_kill_switch_active',
    'agent_kill_switch_active',
    'agent_group_kill_switch_active',
    'tool_kill_switch_active',
    'ai_system_suspended',
    'ai_system_retired',
  ])('kill switch or AI-system state %s: refused', async (reason) => {
    const h = makeDecisionHarness({ killSwitch: { killed: true, reason } });

    await expect(redeem(h)).resolves.toMatchObject({
      decision: 'DENY',
      reason,
    });
    expect(h.decisions[0]).toMatchObject({
      outcome: 'DENY',
      reasonCodes: [reason],
    });
    expect(h.client.authorizationGrant.updateMany).not.toHaveBeenCalled();
  });

  it('OpenFGA entitlement withdrawn: refused', async () => {
    const h = makeDecisionHarness({ openFgaAllowed: false });

    await expect(redeem(h)).resolves.toMatchObject({
      decision: 'DENY',
      reason: 'not_authorized',
    });
  });

  it.each([
    [{ status: 'REVOKED' }, 'task_status_revoked'],
    [{ expiresAt: new Date(Date.now() - 1000) }, 'task_outside_time_window'],
    [{ assignedAgentId: 'agent-2' }, 'not_assigned_agent'],
    [
      { forbiddenActions: [{ toolId: 'edr', actionId: 'isolate-host' }] },
      'forbidden_action',
    ],
  ])(
    'task scope or TTL changed (%o): refused with %s',
    async (task, reason) => {
      const h = makeDecisionHarness({ task });

      await expect(redeem(h)).resolves.toMatchObject({
        decision: 'DENY',
        reason,
      });
      expect(h.client.authorizationGrant.updateMany).not.toHaveBeenCalled();
    },
  );

  it("the grant's own execution, counted at issuance, does not exhaust the task", async () => {
    const h = makeDecisionHarness({
      task: { maxExecutions: 1, executionCount: 1 },
    });

    await expect(redeem(h)).resolves.toMatchObject({ decision: 'ALLOW' });
  });

  it('an invalid grant is recorded as a DENY decision without evaluating anything else', async () => {
    const h = makeDecisionHarness();

    const result = await redeem(h, { valid: false, reason: 'grant_mismatch' });

    expect(result).toMatchObject({
      decision: 'DENY',
      reason: 'grant_mismatch',
    });
    expect(h.decisions[0]).toMatchObject({
      outcome: 'DENY',
      stage: 'GRANT_REDEMPTION',
      reasonCodes: ['grant_mismatch'],
    });
    expect(h.checkAll).not.toHaveBeenCalled();
  });

  it('losing the single-use race at consume time records DENY grant_already_consumed', async () => {
    const h = makeDecisionHarness({ grantConsumeCount: 0 });

    await expect(redeem(h)).resolves.toMatchObject({
      decision: 'DENY',
      reason: 'grant_already_consumed',
    });
    expect(h.decisions[0]).toMatchObject({
      outcome: 'DENY',
      reasonCodes: ['grant_already_consumed'],
    });
  });

  it('decision write failure at redemption: 503', async () => {
    const h = makeDecisionHarness({ decisionWriteFails: true });

    await expect(redeem(h)).rejects.toBeInstanceOf(
      EnforcementDependencyUnavailableException,
    );
  });
});
