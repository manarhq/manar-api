import { ForbiddenException } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import { describe, expect, it, vi } from 'vitest';
import type { AgentContext } from '../agent-mtls/agent-context';
import type { ApprovalRequestService } from '../approvals/approval-request.service';
import type { GrantService } from '../approvals/grant.service';
import type { AuditService } from '../audit/audit.service';
import {
  makeDecisionHarness,
  type DecisionHarnessOptions,
} from '../authorization/decision-pipeline.fakes';
import { EnforcementDependencyUnavailableException } from '../common/fail-closed/fail-closed';
import type { AppConfig } from '../config/env.validation';
import type { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import type { TemporalClientService } from '../temporal/temporal-client.service';
import type { CredentialBrokerService } from './credential-broker.service';
import { ToolInvocationService } from './tool-invocation.service';

/**
 * Both agent doors (REST `tools/invoke`, MCP `tools/call`) go through
 * `ToolInvocationService`. These drive it with a real `AuthorizationService`
 * (in-memory tenant client) and a fake broker, to prove the ordering ADR-003
 * requires: the decision commits, then the broker runs, and a decision that
 * cannot be written means the broker never runs (ADR-003 consequence G14).
 */

const AGENT = {
  tenant: { id: 'tenant-1' },
  agent: { id: 'agent-1' },
} as unknown as AgentContext;

const INPUT = {
  taskId: 'task-1',
  toolId: 'edr',
  actionId: 'isolate-host',
  resource: 'host-1',
  params: { reason: 'ransomware' },
};

function setup(
  options: DecisionHarnessOptions & {
    grantValid?: boolean;
    /** What `GrantService.findRedeemableGrantToken` answers (MCP door). */
    storedGrantToken?: string | null | Error;
    /** What `ApprovalRequestService.findPendingMatch` answers (MCP door). */
    pendingMatch?:
      | {
          id: string;
          riskScore: number;
          policyVersionId: string | null;
          requiredReason: string;
        }
      | null
      | Error;
    workflowStartFails?: boolean;
    /** What `ApprovalRequestService.expireIfPending` answers. */
    expireResult?: { expired: boolean; status: string | null };
  } = {},
) {
  const h = makeDecisionHarness(options);
  const brokerInvoke = vi.fn(() => {
    h.events.push('broker');
    return Promise.resolve({ success: true, data: { isolated: true } });
  });
  const verifyGrant = vi.fn(() =>
    Promise.resolve(
      options.grantValid === false
        ? { valid: false as const, reason: 'grant_already_consumed' }
        : { valid: true as const, grantId: 'grant-1' },
    ),
  );
  const answer = <T>(value: T | Error) =>
    value instanceof Error ? Promise.reject(value) : Promise.resolve(value);
  const findRedeemableGrantToken = vi.fn(() =>
    answer(options.storedGrantToken ?? null),
  );
  const findPendingMatch = vi.fn(() => answer(options.pendingMatch ?? null));
  const createApproval = vi.fn().mockResolvedValue({ id: 'approval-1' });
  const workflowStart = vi.fn(() =>
    options.workflowStartFails
      ? Promise.reject(new Error('temporal unavailable'))
      : Promise.resolve(undefined),
  );
  const expireIfPending = vi
    .fn()
    .mockResolvedValue(
      options.expireResult ?? { expired: true, status: 'EXPIRED' },
    );
  const auditRecordSafely = vi.fn().mockResolvedValue(undefined);
  const service = new ToolInvocationService(
    h.service,
    { invoke: brokerInvoke } as unknown as CredentialBrokerService,
    {
      getClient: () => Promise.resolve(h.tenantClient),
    } as unknown as TenantDatabaseManager,
    {
      create: createApproval,
      findPendingMatch,
      expireIfPending,
    } as unknown as ApprovalRequestService,
    { verifyGrant, findRedeemableGrantToken } as unknown as GrantService,
    {
      workflow: { start: workflowStart },
      taskQueue: 'q',
    } as unknown as TemporalClientService,
    { get: () => 60_000 } as unknown as ConfigService<AppConfig, true>,
    { recordSafely: auditRecordSafely } as unknown as AuditService,
  );
  return {
    h,
    service,
    brokerInvoke,
    verifyGrant,
    auditRecordSafely,
    findRedeemableGrantToken,
    findPendingMatch,
    createApproval,
    workflowStart,
    expireIfPending,
  };
}

describe('ToolInvocationService: decision before execution (ADR-003, S1)', () => {
  it('commits the decision before the broker runs and hands the broker its id', async () => {
    const { h, service, brokerInvoke } = setup();

    await service.invoke(AGENT, INPUT, 'REST');

    expect(h.events).toEqual(['increment:tx', 'decision:tx', 'broker']);
    expect(brokerInvoke).toHaveBeenCalledWith(
      h.tenantClient,
      expect.objectContaining({ decisionId: 'decision-1' }),
    );
  });

  it('G14: a decision-record write failure is a 503 and nothing executes', async () => {
    const { service, brokerInvoke } = setup({ decisionWriteFails: true });

    await expect(service.invoke(AGENT, INPUT, 'REST')).rejects.toBeInstanceOf(
      EnforcementDependencyUnavailableException,
    );
    expect(brokerInvoke).not.toHaveBeenCalled();
  });

  it('the MCP door records channel MCP', async () => {
    const { h, service } = setup();

    await service.invoke(AGENT, INPUT, 'MCP');

    expect(h.decisions[0]).toMatchObject({ channel: 'MCP' });
  });

  it('DENY carries the decision id to the caller and never reaches the broker', async () => {
    const { service, brokerInvoke } = setup({ openFgaAllowed: false });

    const error = await service
      .invoke(AGENT, INPUT, 'REST')
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ForbiddenException);
    expect((error as ForbiddenException).getResponse()).toEqual({
      decision: 'DENY',
      reason: 'not_authorized',
      decisionId: 'decision-1',
    });
    expect(brokerInvoke).not.toHaveBeenCalled();
  });
});
describe('ToolInvocationService: grant redemption re-runs the decision (S6/F7)', () => {
  const WITH_GRANT = { ...INPUT, grantToken: 'signed-grant' };

  it('policy now DENY: refused with 403, DENY decision recorded, broker never called, rejection audited with the decision id', async () => {
    const { h, service, brokerInvoke, auditRecordSafely } = setup({
      policy: { effect: 'DENY', policyId: 'p', policyVersionId: 'pv-2' },
    });

    await expect(
      service.invoke(AGENT, WITH_GRANT, 'REST'),
    ).rejects.toBeInstanceOf(ForbiddenException);

    expect(brokerInvoke).not.toHaveBeenCalled();
    expect(h.decisions[0]).toMatchObject({
      outcome: 'DENY',
      stage: 'GRANT_REDEMPTION',
      reasonCodes: ['policy_denied'],
    });
    expect(auditRecordSafely).toHaveBeenCalledWith(
      h.tenantClient,
      'tenant-1',
      expect.objectContaining({
        eventType: 'approval.grant_rejected',
        data: expect.objectContaining({
          decisionId: 'decision-1',
          reason: 'policy_denied',
        }) as unknown,
      }),
    );
  });

  it('still allowed: grant consumed with the decision, then executed under the redemption decision id', async () => {
    const { h, service, brokerInvoke, auditRecordSafely } = setup();

    await service.invoke(AGENT, WITH_GRANT, 'MCP');

    expect(h.events).toEqual(['consume:tx', 'decision:tx', 'broker']);
    expect(brokerInvoke).toHaveBeenCalledWith(
      h.tenantClient,
      expect.objectContaining({ decisionId: 'decision-1' }),
    );
    expect(auditRecordSafely).toHaveBeenCalledWith(
      h.tenantClient,
      'tenant-1',
      expect.objectContaining({
        eventType: 'approval.grant_redeemed',
        data: expect.objectContaining({
          decisionId: 'decision-1',
          grantId: 'grant-1',
        }) as unknown,
      }),
    );
  });

  it('an already-consumed grant is a recorded DENY', async () => {
    const { h, service, brokerInvoke } = setup({ grantValid: false });

    await expect(
      service.invoke(AGENT, WITH_GRANT, 'REST'),
    ).rejects.toBeInstanceOf(ForbiddenException);
    expect(brokerInvoke).not.toHaveBeenCalled();
    expect(h.decisions[0]).toMatchObject({
      outcome: 'DENY',
      reasonCodes: ['grant_already_consumed'],
    });
  });
});

describe('ToolInvocationService: the MCP door completes an approved action (ADR-0007)', () => {
  const NEEDS_APPROVAL = {
    policy: {
      effect: 'APPROVAL_REQUIRED' as const,
      policyId: 'p',
      policyVersionId: 'pv-1',
    },
  };

  it('a repeated call with an approved grant on record redeems it: verified, re-decided, consumed, executed', async () => {
    const { h, service, brokerInvoke, verifyGrant, findRedeemableGrantToken } =
      setup({ ...NEEDS_APPROVAL, storedGrantToken: 'server-held-grant' });

    await service.invoke(AGENT, INPUT, 'MCP');

    expect(findRedeemableGrantToken).toHaveBeenCalledWith(h.tenantClient, {
      tenantId: 'tenant-1',
      agentId: 'agent-1',
      ...INPUT,
    });
    expect(verifyGrant).toHaveBeenCalledWith(
      h.tenantClient,
      expect.objectContaining({ ...INPUT, grantToken: 'server-held-grant' }),
    );
    expect(h.events).toEqual(['consume:tx', 'decision:tx', 'broker']);
    expect(h.decisions[0]).toMatchObject({
      outcome: 'ALLOW',
      stage: 'GRANT_REDEMPTION',
      channel: 'MCP',
      grantId: 'grant-1',
    });
    expect(brokerInvoke).toHaveBeenCalledOnce();
  });

  it('kill switch engaged after approval: the redemption is a recorded DENY and nothing executes', async () => {
    const { h, service, brokerInvoke } = setup({
      storedGrantToken: 'server-held-grant',
      killSwitch: { killed: true, reason: 'agent_kill_switch_active' },
    });

    const error = await service
      .invoke(AGENT, INPUT, 'MCP')
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ForbiddenException);
    expect(h.decisions[0]).toMatchObject({
      outcome: 'DENY',
      stage: 'GRANT_REDEMPTION',
      reasonCodes: ['agent_kill_switch_active'],
    });
    expect(brokerInvoke).not.toHaveBeenCalled();
  });

  it('a grant-store failure during the lookup fails closed (503) and nothing executes', async () => {
    const { h, service, brokerInvoke } = setup({
      storedGrantToken: new Error('connection terminated'),
    });

    await expect(service.invoke(AGENT, INPUT, 'MCP')).rejects.toBeInstanceOf(
      EnforcementDependencyUnavailableException,
    );
    expect(h.decisions).toHaveLength(0);
    expect(brokerInvoke).not.toHaveBeenCalled();
  });

  const OPEN = {
    id: 'approval-open',
    riskScore: 10,
    policyVersionId: 'pv-1',
    requiredReason: 'policy_requires_approval',
  };

  it('still waiting: a repeated call returns the open approval instead of opening a second one, and audits the reuse', async () => {
    const {
      h,
      service,
      createApproval,
      workflowStart,
      brokerInvoke,
      expireIfPending,
      auditRecordSafely,
    } = setup({
      ...NEEDS_APPROVAL,
      pendingMatch: OPEN,
    });

    const outcome = await service.invoke(AGENT, INPUT, 'MCP');

    expect(outcome).toMatchObject({
      status: 'PENDING',
      approvalId: 'approval-open',
    });
    expect(h.decisions[0]).toMatchObject({
      outcome: 'APPROVAL_REQUIRED',
      channel: 'MCP',
    });
    expect(createApproval).not.toHaveBeenCalled();
    expect(workflowStart).not.toHaveBeenCalled();
    expect(expireIfPending).not.toHaveBeenCalled();
    expect(brokerInvoke).not.toHaveBeenCalled();
    expect(auditRecordSafely).toHaveBeenCalledWith(
      h.tenantClient,
      'tenant-1',
      expect.objectContaining({
        eventType: 'approval.reused',
        data: { decisionId: 'decision-1', approvalRequestId: 'approval-open' },
      }),
    );
  });

  it('the fresh decision scores higher than the open approval: the open one is superseded and a new approval shows the new risk', async () => {
    const { service, createApproval, expireIfPending, auditRecordSafely } =
      setup({
        ...NEEDS_APPROVAL,
        riskScore: 90,
        pendingMatch: { ...OPEN, riskScore: 40 },
      });

    const outcome = await service.invoke(AGENT, INPUT, 'MCP');

    expect(expireIfPending).toHaveBeenCalledWith(
      expect.anything(),
      'approval-open',
      'superseded',
    );
    expect(createApproval).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ riskScore: 90 }),
    );
    expect(outcome).toMatchObject({
      status: 'PENDING',
      approvalId: 'approval-1',
      riskScore: 90,
    });
    expect(auditRecordSafely).toHaveBeenCalledWith(
      expect.anything(),
      'tenant-1',
      expect.objectContaining({
        eventType: 'approval.superseded',
        data: expect.objectContaining({
          approvalRequestId: 'approval-open',
          decisionId: 'decision-1',
        }) as unknown,
      }),
    );
  });

  it('a person approved the open request before it could be superseded: the lost supersede is audited', async () => {
    const { service, createApproval, auditRecordSafely } = setup({
      ...NEEDS_APPROVAL,
      riskScore: 90,
      pendingMatch: { ...OPEN, riskScore: 40 },
      expireResult: { expired: false, status: 'APPROVED' },
    });

    await service.invoke(AGENT, INPUT, 'MCP');

    expect(createApproval).toHaveBeenCalledOnce();
    expect(auditRecordSafely).toHaveBeenCalledWith(
      expect.anything(),
      'tenant-1',
      expect.objectContaining({
        eventType: 'approval.superseded',
        data: expect.objectContaining({
          approvalRequestId: 'approval-open',
          supersedeLost: true,
          statusFound: 'APPROVED',
        }) as unknown,
      }),
    );
  });

  it('same risk under another policy version: superseded, not reused', async () => {
    const { service, createApproval, expireIfPending } = setup({
      ...NEEDS_APPROVAL,
      pendingMatch: { ...OPEN, policyVersionId: 'pv-0' },
    });

    await service.invoke(AGENT, INPUT, 'MCP');

    expect(expireIfPending).toHaveBeenCalledWith(
      expect.anything(),
      'approval-open',
      'superseded',
    );
    expect(createApproval).toHaveBeenCalledOnce();
  });

  it('the approval workflow fails to start: the new request is expired so a repeated call is not stuck on it', async () => {
    const { service, expireIfPending } = setup({
      ...NEEDS_APPROVAL,
      workflowStartFails: true,
    });

    await expect(service.invoke(AGENT, INPUT, 'MCP')).rejects.toThrow(
      'temporal unavailable',
    );
    expect(expireIfPending).toHaveBeenCalledWith(
      expect.anything(),
      'approval-1',
      'no_workflow',
    );
  });

  it('an approval-store failure during the pending lookup fails closed (503)', async () => {
    const { service, createApproval } = setup({
      ...NEEDS_APPROVAL,
      pendingMatch: new Error('connection terminated'),
    });

    await expect(service.invoke(AGENT, INPUT, 'MCP')).rejects.toBeInstanceOf(
      EnforcementDependencyUnavailableException,
    );
    expect(createApproval).not.toHaveBeenCalled();
  });

  it('the REST door keeps explicit grant tokens: no server-side grant or pending lookup', async () => {
    const {
      service,
      findRedeemableGrantToken,
      findPendingMatch,
      createApproval,
    } = setup({ ...NEEDS_APPROVAL, storedGrantToken: 'server-held-grant' });

    const outcome = await service.invoke(AGENT, INPUT, 'REST');

    expect(outcome).toMatchObject({
      status: 'PENDING',
      approvalId: 'approval-1',
    });
    expect(findRedeemableGrantToken).not.toHaveBeenCalled();
    expect(findPendingMatch).not.toHaveBeenCalled();
    expect(createApproval).toHaveBeenCalledOnce();
  });
});
