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
  const auditRecordSafely = vi.fn().mockResolvedValue(undefined);
  const service = new ToolInvocationService(
    h.service,
    { invoke: brokerInvoke } as unknown as CredentialBrokerService,
    {
      getClient: () => Promise.resolve(h.tenantClient),
    } as unknown as TenantDatabaseManager,
    {
      create: vi.fn().mockResolvedValue({ id: 'approval-1' }),
    } as unknown as ApprovalRequestService,
    { verifyGrant } as unknown as GrantService,
    {
      workflow: { start: vi.fn().mockResolvedValue(undefined) },
      taskQueue: 'q',
    } as unknown as TemporalClientService,
    { get: () => 60_000 } as unknown as ConfigService<AppConfig, true>,
    { recordSafely: auditRecordSafely } as unknown as AuditService,
  );
  return { h, service, brokerInvoke, verifyGrant, auditRecordSafely };
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
