import { describe, expect, it, vi } from 'vitest';

import { KillSwitchService } from './kill-switch.service';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';

/**
 * CLAUDE.md §7: `GovernanceState SUSPENDED` → `RuntimeState BLOCKED`.
 * CLAUDE.md §3's demo chain, steps 18-20: "Governance Manager suspends the AI
 * system → further governed actions blocked".
 *
 * Phase 0 finding N2: `AiSystemsService.transitionState` changed a governance
 * column and nothing read it at authorization time, so the demo's closing move
 * did nothing. These tests pin the derivation.
 *
 * The runtime state is DERIVED from the governance state rather than mirrored
 * into a second `KillSwitch` row. Two facts can disagree — a suspend that
 * forgets to write the row, or a row that outlives the suspend. One fact
 * cannot.
 */

type FakeRow = Record<string, unknown>;

/**
 * A deliberately faithful double: `aiSystem.findMany` honours the
 * `lifecycleState: { in: [...] }` filter rather than returning everything.
 * A double that ignored the WHERE clause would pass just as happily against
 * an implementation that forgot to filter at all, which would block every
 * agent whose AI system merely exists.
 */
function fakeClient(systems: FakeRow[], links: FakeRow[]): TenantPrismaClient {
  return {
    killSwitch: { findFirst: vi.fn(() => Promise.resolve(null)) },
    agentGroupMembership: { findMany: vi.fn(() => Promise.resolve([])) },
    tool: { findUnique: vi.fn(() => Promise.resolve(null)) },
    aiSystemAgentLink: {
      findMany: vi.fn(({ where }: { where: { agentId: string } }) =>
        Promise.resolve(links.filter((link) => link.agentId === where.agentId)),
      ),
    },
    aiSystem: {
      findMany: vi.fn(
        ({
          where,
        }: {
          where: { id: { in: string[] }; lifecycleState: { in: string[] } };
        }) =>
          Promise.resolve(
            systems.filter(
              (system) =>
                where.id.in.includes(system.id as string) &&
                where.lifecycleState.in.includes(
                  system.lifecycleState as string,
                ),
            ),
          ),
      ),
    },
  } as unknown as TenantPrismaClient;
}

function clientWith(options: {
  link?: FakeRow | null;
  aiSystem?: FakeRow | null;
}): TenantPrismaClient {
  return fakeClient(
    options.aiSystem ? [options.aiSystem] : [],
    options.link ? [options.link] : [],
  );
}

function serviceWithNoPlatformKill(): KillSwitchService {
  return new KillSwitchService(
    { recordSafely: vi.fn(() => Promise.resolve(undefined)) } as never,
    { isActive: vi.fn(() => Promise.resolve(false)) } as never,
  );
}

describe('checkAll — AI-system governance gate', () => {
  it('blocks an agent whose AI system is SUSPENDED', async () => {
    const service = serviceWithNoPlatformKill();
    const client = clientWith({
      link: { aiSystemId: 'ai-1', agentId: 'agent-1' },
      aiSystem: {
        id: 'ai-1',
        name: 'Security Remediation Agent',
        lifecycleState: 'SUSPENDED',
      },
    });

    const result = await service.checkAll(client, 'tenant-1', {
      agentId: 'agent-1',
    });

    expect(result.killed).toBe(true);
    expect(result.scope).toBe('AI_SYSTEM');
    expect(result.reason).toBe('ai_system_suspended');
  });

  it('blocks an agent whose AI system is RETIRED', async () => {
    const service = serviceWithNoPlatformKill();
    const client = clientWith({
      link: { aiSystemId: 'ai-1', agentId: 'agent-1' },
      aiSystem: {
        id: 'ai-1',
        name: 'Decommissioned',
        lifecycleState: 'RETIRED',
      },
    });

    const result = await service.checkAll(client, 'tenant-1', {
      agentId: 'agent-1',
    });

    expect(result.killed).toBe(true);
    expect(result.scope).toBe('AI_SYSTEM');
    expect(result.reason).toBe('ai_system_retired');
  });

  it('allows an agent whose AI system is ACTIVE', async () => {
    const service = serviceWithNoPlatformKill();
    const client = clientWith({
      link: { aiSystemId: 'ai-1', agentId: 'agent-1' },
      aiSystem: {
        id: 'ai-1',
        name: 'Security Remediation Agent',
        lifecycleState: 'ACTIVE',
      },
    });

    const result = await service.checkAll(client, 'tenant-1', {
      agentId: 'agent-1',
    });

    expect(result.killed).toBe(false);
  });

  it('allows an agent that is linked to no AI system at all', async () => {
    const service = serviceWithNoPlatformKill();
    const client = clientWith({ link: null });

    const result = await service.checkAll(client, 'tenant-1', {
      agentId: 'unlinked',
    });

    expect(result.killed).toBe(false);
  });

  it('blocks when ANY linked AI system is suspended, not only when all are', async () => {
    // An agent may be linked to more than one AI system. The strictest state
    // wins: if any owning system is suspended, the agent stops.
    const service = serviceWithNoPlatformKill();
    const client = fakeClient(
      [
        { id: 'ai-1', name: 'Healthy', lifecycleState: 'ACTIVE' },
        { id: 'ai-2', name: 'Suspended one', lifecycleState: 'SUSPENDED' },
      ],
      [
        { aiSystemId: 'ai-1', agentId: 'agent-1' },
        { aiSystemId: 'ai-2', agentId: 'agent-1' },
      ],
    );

    const result = await service.checkAll(client, 'tenant-1', {
      agentId: 'agent-1',
    });

    expect(result.killed).toBe(true);
    expect(result.scope).toBe('AI_SYSTEM');
  });
});
