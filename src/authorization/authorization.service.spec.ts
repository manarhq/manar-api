import { describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../audit/audit.service';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import type { KillSwitchService } from '../kill-switches/kill-switch.service';
import type { PolicyEngine } from '../policy/policy-engine.service';
import type { RiskEngine } from '../risk/risk-engine.service';
import type { TasksService } from '../tasks/tasks.service';
import { AuthorizationService } from './authorization.service';
import type { OpenFgaClientService } from './openfga-client.service';
import { allowAllCatalog } from '../platform/catalog.fakes';

/** Only what the fail-closed path touches: the `Decision` insert. */
const tenantClient = {
  decision: { create: vi.fn().mockResolvedValue({ id: 'decision-1' }) },
} as unknown as TenantPrismaClient;

const REQUEST = {
  taskId: 'task-1',
  toolId: 'entra',
  actionId: 'disable_user',
  resource: 'user-1',
};

function makeService(overrides: {
  checkAll?: () => Promise<unknown>;
  getTaskOrThrow?: () => Promise<unknown>;
}) {
  const recordSafely = vi.fn().mockResolvedValue(undefined);
  const service = new AuthorizationService(
    {
      getTaskOrThrow: overrides.getTaskOrThrow ?? vi.fn(),
    } as unknown as TasksService,
    {} as OpenFgaClientService,
    {} as PolicyEngine,
    {} as RiskEngine,
    { recordSafely } as unknown as AuditService,
    {
      checkAll:
        overrides.checkAll ?? (() => Promise.resolve({ killed: false })),
    } as unknown as KillSwitchService,
    allowAllCatalog(),
  );
  return { service, recordSafely };
}

describe('AuthorizationService.authorize fails closed (S32, S61)', () => {
  it('denies with enforcement_dependency_unavailable when the kill-switch lookup fails', async () => {
    const { service, recordSafely } = makeService({
      checkAll: () => Promise.reject(new Error('Connection terminated')),
    });

    await expect(
      service.authorize(tenantClient, 't1', 'agent-1', REQUEST),
    ).resolves.toEqual({
      decision: 'DENY',
      reason: 'enforcement_dependency_unavailable',
      decisionId: 'decision-1',
    });
    expect(recordSafely).toHaveBeenCalledWith(
      expect.anything(),
      't1',
      expect.objectContaining({
        eventType: 'authorization.denied',
        data: expect.objectContaining({
          reason: 'enforcement_dependency_unavailable',
        }) as unknown,
      }),
    );
  });

  it('denies when a later pipeline step throws an unexpected error', async () => {
    const { service } = makeService({
      getTaskOrThrow: () => Promise.reject(new Error('AncestorChainTooDeep')),
    });

    await expect(
      service.authorize(tenantClient, 't1', 'agent-1', REQUEST),
    ).resolves.toEqual({
      decision: 'DENY',
      reason: 'enforcement_dependency_unavailable',
      decisionId: 'decision-1',
    });
  });
});
