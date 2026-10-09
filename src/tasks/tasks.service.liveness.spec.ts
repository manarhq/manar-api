import { describe, expect, it, vi } from 'vitest';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import type { KillSwitchService } from '../kill-switches/kill-switch.service';
import { TasksService, type TaskRecord } from './tasks.service';

/**
 * ADR-0009, review finding 1: a quarantined (or AGENT-killed) agent must not
 * keep acting through children it delegated. `evaluateFullLiveness` is the
 * gate every path shares (authorize, redemption, agent runtime, delegation),
 * so the ancestors' agents are checked there.
 */
const base: TaskRecord = {
  id: 'child',
  name: 'n',
  description: null,
  parentTaskId: 'parent',
  requesterId: 'u',
  assignedAgentId: 'agent-child',
  status: 'ACTIVE',
  startsAt: new Date('2026-01-01T00:00:00Z'),
  expiresAt: new Date('2099-01-01T00:00:00Z'),
  maxExecutions: null,
  executionCount: 0,
  allowedToolActions: [],
  allowedResourceSelectors: [],
  forbiddenActions: [],
  riskCeiling: 20,
  createdAt: new Date('2026-01-01T00:00:00Z'),
};
const parent: TaskRecord = {
  ...base,
  id: 'parent',
  parentTaskId: null,
  assignedAgentId: 'agent-parent',
};

function client() {
  return {
    task: {
      findUnique: vi.fn(({ where }: { where: { id: string } }) =>
        Promise.resolve(where.id === 'parent' ? parent : null),
      ),
    },
  } as unknown as TenantPrismaClient;
}

/** The real per-agent gate is `KillSwitchService.checkAgent`; this fake answers per agent id. */
function serviceWith(stopped: Record<string, string>) {
  const checkAgent = vi.fn((_c: unknown, _t: string, agentId: string) =>
    Promise.resolve(
      stopped[agentId]
        ? { killed: true, reason: stopped[agentId] }
        : { killed: false },
    ),
  );
  const service = new TasksService(
    {} as never,
    {} as never,
    {
      checkAgent,
    } as unknown as KillSwitchService,
  );
  return { service, checkAgent };
}

const now = new Date('2026-10-09T00:00:00Z');

describe('evaluateFullLiveness: the agents of ancestor tasks', () => {
  for (const reason of [
    'agent_quarantined',
    'agent_kill_switch_active',
    'ai_system_suspended',
    'agent_status_revoked',
  ]) {
    it(`denies a child whose parent agent is stopped (${reason})`, async () => {
      const { service } = serviceWith({ 'agent-parent': reason });
      await expect(
        service.evaluateFullLiveness(client(), 't', base, now),
      ).resolves.toEqual({ ok: false, reason: `ancestor_${reason}` });
    });
  }

  it('allows the child when no ancestor agent is stopped', async () => {
    const { service, checkAgent } = serviceWith({
      someone: 'agent_quarantined',
    });
    await expect(
      service.evaluateFullLiveness(client(), 't', base, now),
    ).resolves.toEqual({ ok: true });
    expect(checkAgent).toHaveBeenCalledWith(
      expect.anything(),
      't',
      'agent-parent',
    );
  });

  it('a lookup failure propagates (callers fail closed)', async () => {
    const { service, checkAgent } = serviceWith({});
    checkAgent.mockRejectedValueOnce(new Error('db down'));
    await expect(
      service.evaluateFullLiveness(client(), 't', base, now),
    ).rejects.toThrow('db down');
  });

  it('a root task checks no other agent', async () => {
    const { service, checkAgent } = serviceWith({});
    await service.evaluateFullLiveness(client(), 't', parent, now);
    expect(checkAgent).not.toHaveBeenCalled();
  });
});
