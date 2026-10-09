import type { ConfigService } from '@nestjs/config';
import { describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../audit/audit.service';
import { makeTask } from '../authorization/decision-pipeline.fakes';
import type { AppConfig } from '../config/env.validation';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import type { PolicyEngine } from '../policy/policy-engine.service';
import type { RiskEngine } from '../risk/risk-engine.service';
import type { TasksService } from '../tasks/tasks.service';
import { GrantService } from './grant.service';

/**
 * The approval state change is conditional (PENDING -> X only) and, for
 * APPROVE, atomic with grant issuance. A request that turned EXPIRED (timeout,
 * or superseded by the MCP door, ADR-0007) or was decided elsewhere between
 * the read and the write keeps that state: no grant, no approval audit.
 * Unit level with a transaction mock: the race window is between two awaits
 * and cannot be hit deterministically on the real stack.
 */

const REQUEST = {
  id: 'approval-1',
  status: 'PENDING',
  taskId: 'task-1',
  agentId: 'agent-1',
  toolId: 'edr',
  actionId: 'isolate-host',
  resource: 'host-1',
  params: { reason: 'x' },
  grant: null,
};

function setup(options: { statusAfterRace?: string } = {}) {
  const events: string[] = [];
  let status = 'PENDING';
  const raced = options.statusAfterRace;
  const client = {
    approvalRequest: {
      findUnique: vi.fn(() =>
        Promise.resolve({ ...REQUEST, status, grant: null }),
      ),
      updateMany: vi.fn(
        ({ data }: { where: unknown; data: { status: string } }) => {
          // The competing write lands after finalizeDecision's read.
          if (raced) status = raced;
          if (status !== 'PENDING') return Promise.resolve({ count: 0 });
          status = data.status;
          events.push(`status:${data.status}`);
          return Promise.resolve({ count: 1 });
        },
      ),
      update: vi.fn(({ data }: { data: { status: string } }) => {
        status = data.status;
        events.push(`status:${data.status}`);
        return Promise.resolve({});
      }),
    },
    approvalDecision: { create: vi.fn().mockResolvedValue({}) },
    task: {
      findUnique: vi.fn().mockResolvedValue(makeTask()),
      update: vi.fn(() => {
        events.push('increment');
        return Promise.resolve({});
      }),
      updateMany: vi.fn(() => {
        events.push('increment');
        return Promise.resolve({ count: 1 });
      }),
    },
    agent: {
      findUnique: vi
        .fn()
        .mockResolvedValue({ id: 'agent-1', status: 'ACTIVE' }),
    },
    authorizationGrant: {
      create: vi.fn(({ data }: { data: Record<string, unknown> }) => {
        events.push('grant');
        return Promise.resolve({ ...data, id: 'grant-1' });
      }),
    },
    $transaction: vi.fn(async (fn: (tx: unknown) => Promise<unknown>) => {
      events.push('tx:begin');
      const result = await fn(client);
      events.push('tx:commit');
      return result;
    }),
  };
  const recordSafely = vi.fn().mockResolvedValue(undefined);
  const incrementExecutionCount = vi.fn(
    async (c: { task: { update: () => Promise<unknown> } }) => {
      await c.task.update();
      return true;
    },
  );
  const tasksService = {
    evaluateFullLiveness: vi.fn().mockResolvedValue({ ok: true }),
    incrementExecutionCount,
  } as unknown as TasksService;
  const service = new GrantService(
    tasksService,
    {
      evaluate: vi.fn().mockResolvedValue({
        effect: 'APPROVAL_REQUIRED',
        policyVersionId: 'pv-1',
      }),
    } as unknown as PolicyEngine,
    {
      score: vi.fn().mockResolvedValue({ riskScore: 40, reasonCodes: [] }),
    } as unknown as RiskEngine,
    {
      get: (key: string) =>
        key === 'APPROVAL_GRANT_TTL_MS' ? 300_000 : 'secret',
    } as unknown as ConfigService<AppConfig, true>,
    { recordSafely } as unknown as AuditService,
  );
  return {
    service,
    tenantClient: client as unknown as TenantPrismaClient,
    client,
    events,
    recordSafely,
    incrementExecutionCount,
  };
}

const APPROVE = {
  tenantId: 'tenant-1',
  approvalRequestId: 'approval-1',
  decision: 'APPROVE' as const,
  approverId: 'human-1',
};

const eventTypes = (recordSafely: ReturnType<typeof vi.fn>) =>
  recordSafely.mock.calls.map(
    (call) => (call[2] as { eventType: string }).eventType,
  );

describe('GrantService.finalizeDecision: conditional, atomic state change', () => {
  it('APPROVE: claims the PENDING row, counts the execution and issues the grant in one transaction', async () => {
    const { service, tenantClient, events, recordSafely } = setup();

    await expect(
      service.finalizeDecision(tenantClient, APPROVE),
    ).resolves.toEqual({ status: 'APPROVED', grantId: 'grant-1' });
    expect(events).toEqual([
      'tx:begin',
      'status:APPROVED',
      'increment',
      'grant',
      'tx:commit',
    ]);
    expect(eventTypes(recordSafely)).toEqual([
      'approval.grant_issued',
      'approval.approved',
    ]);
  });

  it('APPROVE racing an expiry (timeout or MCP supersede): no grant, no execution counted, EXPIRED returned, no approval audit', async () => {
    const {
      service,
      tenantClient,
      client,
      recordSafely,
      incrementExecutionCount,
    } = setup({ statusAfterRace: 'EXPIRED' });

    await expect(
      service.finalizeDecision(tenantClient, APPROVE),
    ).resolves.toEqual({ status: 'EXPIRED' });
    expect(client.authorizationGrant.create).not.toHaveBeenCalled();
    expect(incrementExecutionCount).not.toHaveBeenCalled();
    expect(client.approvalRequest.update).not.toHaveBeenCalled();
    expect(eventTypes(recordSafely)).toEqual([]);
  });

  it('DENY racing an expiry: the EXPIRED state stands and no denial is audited', async () => {
    const { service, tenantClient, client, recordSafely } = setup({
      statusAfterRace: 'EXPIRED',
    });

    await expect(
      service.finalizeDecision(tenantClient, { ...APPROVE, decision: 'DENY' }),
    ).resolves.toEqual({ status: 'EXPIRED' });
    expect(client.approvalRequest.update).not.toHaveBeenCalled();
    expect(eventTypes(recordSafely)).toEqual([]);
  });
});

describe('GrantService.expire: conditional', () => {
  it('only moves a PENDING request to EXPIRED, never one decided in the meantime', async () => {
    const { service, tenantClient, client } = setup({
      statusAfterRace: 'APPROVED',
    });

    await service.expire(tenantClient, 'approval-1');

    expect(client.approvalRequest.updateMany).toHaveBeenCalledWith({
      where: { id: 'approval-1', status: 'PENDING' },
      data: { status: 'EXPIRED' },
    });
    expect(client.approvalRequest.update).not.toHaveBeenCalled();
  });
});
