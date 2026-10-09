import { describe, expect, it } from 'vitest';
import { computeParameterHash } from '../approvals/parameter-hash.util';
import { EnforcementDependencyUnavailableException } from '../common/fail-closed/fail-closed';
import { makeDecisionHarness } from './decision-pipeline.fakes';

/**
 * ADR-003 / security finding S1: a durable `Decision` row commits for every
 * action request before anything executes, and a failure to write it is a
 * 503 with nothing executed. And S6/F7 (spec §6.2): redeeming an approval
 * grant re-runs the whole decision against current state.
 */

const REQUEST = {
  taskId: 'task-1',
  toolId: 'edr',
  actionId: 'isolate-host',
  resource: 'host-1',
};
const PARAMS = { reason: 'ransomware', nested: { b: 2, a: 1 } };

describe('AuthorizationService.authorize records a durable Decision (ADR-003, S1)', () => {
  it('ALLOW: writes the decision with its inputs, in the same transaction as the execution-count increment', async () => {
    const h = makeDecisionHarness();

    const result = await h.service.authorize(
      h.tenantClient,
      'tenant-1',
      'agent-1',
      REQUEST,
      { channel: 'REST', params: PARAMS },
    );

    expect(result).toMatchObject({
      decision: 'ALLOW',
      decisionId: 'decision-1',
    });
    expect(h.decisions).toHaveLength(1);
    expect(h.decisions[0]).toMatchObject({
      outcome: 'ALLOW',
      stage: 'REQUEST',
      channel: 'REST',
      agentId: 'agent-1',
      taskId: 'task-1',
      toolId: 'edr',
      actionId: 'isolate-host',
      resource: 'host-1',
      policyId: 'policy-1',
      policyVersionId: 'policy-version-1',
      riskScore: 10,
      inputsHash: computeParameterHash({ ...REQUEST, params: PARAMS }),
      correlationId: expect.any(String) as unknown,
    });
    expect((h.decisions[0] as { reasonCodes: string[] }).reasonCodes[0]).toBe(
      'allowed',
    );
    expect(h.events).toEqual(['increment:tx', 'decision:tx']);
  });

  it('DENY: the decision is written and the audit event references it', async () => {
    const h = makeDecisionHarness({
      killSwitch: {
        killed: true,
        scope: 'AI_SYSTEM',
        reason: 'ai_system_suspended',
      },
    });

    const result = await h.service.authorize(
      h.tenantClient,
      'tenant-1',
      'agent-1',
      REQUEST,
      { channel: 'MCP', params: {} },
    );

    expect(result).toEqual({
      decision: 'DENY',
      reason: 'ai_system_suspended',
      decisionId: 'decision-1',
    });
    expect(h.decisions[0]).toMatchObject({
      outcome: 'DENY',
      channel: 'MCP',
      reasonCodes: ['ai_system_suspended'],
    });
    expect(h.recordSafely).toHaveBeenCalledWith(
      h.tenantClient,
      'tenant-1',
      expect.objectContaining({
        eventType: 'authorization.denied',
        data: expect.objectContaining({
          decisionId: 'decision-1',
          reason: 'ai_system_suspended',
        }) as unknown,
      }),
    );
  });

  it('APPROVAL_REQUIRED: the decision carries the decisive reason and the risk reason codes', async () => {
    const h = makeDecisionHarness({ riskScore: 80 });

    const result = await h.service.authorize(
      h.tenantClient,
      'tenant-1',
      'agent-1',
      REQUEST,
      { channel: 'REST', params: {} },
    );

    expect(result).toMatchObject({
      decision: 'APPROVAL_REQUIRED',
      reason: 'risk_ceiling_exceeded',
      decisionId: 'decision-1',
    });
    expect(h.decisions[0]).toMatchObject({
      outcome: 'APPROVAL_REQUIRED',
      reasonCodes: ['risk_ceiling_exceeded', 'baseline'],
      riskScore: 80,
    });
    // Nothing is consumed for a request that will not execute now.
    expect(h.events).toEqual(['decision']);
  });

  it('a dependency failure inside the pipeline is still recorded as a DENY decision', async () => {
    const h = makeDecisionHarness({ killSwitchThrows: true });

    const result = await h.service.authorize(
      h.tenantClient,
      'tenant-1',
      'agent-1',
      REQUEST,
    );

    expect(result).toEqual({
      decision: 'DENY',
      reason: 'enforcement_dependency_unavailable',
      decisionId: 'decision-1',
    });
    expect(h.decisions[0]).toMatchObject({
      outcome: 'DENY',
      channel: 'AUTHORIZE',
    });
  });

  it('losing the execution-limit race at commit time records DENY, never ALLOW', async () => {
    const h = makeDecisionHarness({
      task: { maxExecutions: 1 },
      incrementLoses: true,
    });

    const result = await h.service.authorize(
      h.tenantClient,
      'tenant-1',
      'agent-1',
      REQUEST,
      { channel: 'REST', params: {} },
    );

    expect(result).toMatchObject({
      decision: 'DENY',
      reason: 'task_execution_limit_reached',
    });
    expect(h.decisions[0]).toMatchObject({
      outcome: 'DENY',
      reasonCodes: ['task_execution_limit_reached'],
    });
  });

  it('fails closed with 503 when the decision cannot be written, and never reports ALLOW', async () => {
    const h = makeDecisionHarness({ decisionWriteFails: true });

    await expect(
      h.service.authorize(h.tenantClient, 'tenant-1', 'agent-1', REQUEST, {
        channel: 'REST',
        params: {},
      }),
    ).rejects.toBeInstanceOf(EnforcementDependencyUnavailableException);
    expect(h.recordSafely).not.toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({ eventType: 'authorization.allowed' }),
    );
  });
});
