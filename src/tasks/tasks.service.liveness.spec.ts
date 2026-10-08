import { describe, expect, it, vi } from 'vitest';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
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

const inList = (ids: string[], where: { in: string[] }) =>
  where.in.some((id) => ids.includes(id));

function client(state: { quarantined?: string[]; killed?: string[] }) {
  const quarantineLookup = vi.fn(
    ({ where }: { where: { agentId: { in: string[] } } }) =>
      Promise.resolve(
        inList(state.quarantined ?? [], where.agentId) ? { id: 'q' } : null,
      ),
  );
  const c = {
    task: {
      findUnique: vi.fn(({ where }: { where: { id: string } }) =>
        Promise.resolve(where.id === 'parent' ? parent : null),
      ),
    },
    agentQuarantine: { findFirst: quarantineLookup },
    killSwitch: {
      findFirst: vi.fn(
        ({ where }: { where: { scope: string; targetId: { in: string[] } } }) =>
          Promise.resolve(
            where.scope === 'AGENT' &&
              inList(state.killed ?? [], where.targetId)
              ? { id: 'k' }
              : null,
          ),
      ),
    },
  } as unknown as TenantPrismaClient;
  return Object.assign(c, { quarantineLookup });
}

const service = new TasksService({} as never, {} as never);
const now = new Date('2026-10-09T00:00:00Z');

describe('evaluateFullLiveness: the agents of ancestor tasks', () => {
  it('denies a child whose parent agent is quarantined', async () => {
    await expect(
      service.evaluateFullLiveness(
        client({ quarantined: ['agent-parent'] }),
        base,
        now,
      ),
    ).resolves.toEqual({ ok: false, reason: 'ancestor_agent_quarantined' });
  });

  it('denies a child whose parent agent has an AGENT kill switch', async () => {
    await expect(
      service.evaluateFullLiveness(
        client({ killed: ['agent-parent'] }),
        base,
        now,
      ),
    ).resolves.toEqual({
      ok: false,
      reason: 'ancestor_agent_kill_switch_active',
    });
  });

  it('allows the child when no ancestor agent is stopped', async () => {
    await expect(
      service.evaluateFullLiveness(
        client({ quarantined: ['someone-else'] }),
        base,
        now,
      ),
    ).resolves.toEqual({ ok: true });
  });

  it('a root task makes no ancestor-agent query', async () => {
    const c = client({});
    await service.evaluateFullLiveness(c, parent, now);
    expect(c.quarantineLookup).not.toHaveBeenCalled();
  });
});
