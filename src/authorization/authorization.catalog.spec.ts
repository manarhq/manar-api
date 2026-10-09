import { describe, expect, it, vi } from 'vitest';
import { CatalogService } from '../platform/catalog.service';
import { MANAR_TOOL } from '../tools/manar-actions';
import { makeDecisionHarness } from './decision-pipeline.fakes';

/**
 * The tenant catalog on the decision path (src/platform/catalog.*): a pack-bound task acts only
 * while staff keep its pack enabled, the watcher's built-in connector only while `watcher` is
 * on, and an unreadable catalog denies. Checked on a first request and again at grant redemption.
 */

function catalog(row: unknown, fails = false) {
  return new CatalogService(
    {
      tenantCatalog: {
        findUnique: fails
          ? vi.fn().mockRejectedValue(new Error('control db down'))
          : vi.fn().mockResolvedValue(row),
      },
    } as never,
    {} as never,
    {} as never,
    {} as never,
  );
}
const stored = (features: object, packs: object[] = []) => ({
  features,
  packs,
  model: null,
  updatedBy: 'manar-fleet',
  updatedAt: new Date(),
});

const REQUEST = {
  taskId: 'task-1',
  toolId: 'graph',
  actionId: 'entra.user.password.reset',
  resource: 'user-1',
};
const GRANT = { valid: true as const, grantId: 'grant-1' };

describe('AuthorizationService and the tenant catalog', () => {
  it('denies a pack-bound task whose pack is not enabled, before OpenFGA, and records it', async () => {
    const h = makeDecisionHarness({
      task: { packId: 'it-helpdesk' },
      catalog: catalog(null),
    });
    const result = await h.service.authorize(
      h.tenantClient,
      'tenant-1',
      'agent-1',
      REQUEST,
    );
    expect(result).toMatchObject({
      decision: 'DENY',
      reason: 'pack_not_enabled',
    });
    expect(h.openFgaCheck).not.toHaveBeenCalled();
    expect(h.decisions[0]).toMatchObject({
      outcome: 'DENY',
      reasonCodes: ['pack_not_enabled'],
    });
  });

  it('allows the same task once its pack is enabled', async () => {
    const h = makeDecisionHarness({
      task: { packId: 'it-helpdesk' },
      catalog: catalog(
        stored({}, [{ id: 'it-helpdesk', version: 1, enabled: true }]),
      ),
    });
    const result = await h.service.authorize(
      h.tenantClient,
      'tenant-1',
      'agent-1',
      REQUEST,
    );
    expect(result).toMatchObject({ decision: 'ALLOW' });
  });

  it('denies at grant redemption when the pack was disabled after the approval', async () => {
    const h = makeDecisionHarness({
      task: { packId: 'it-helpdesk' },
      catalog: catalog(
        stored({}, [{ id: 'it-helpdesk', version: 1, enabled: false }]),
      ),
    });
    const result = await h.service.authorizeRedemption(
      h.tenantClient,
      'tenant-1',
      'agent-1',
      REQUEST,
      { channel: 'REST' },
      GRANT,
    );
    expect(result).toMatchObject({
      decision: 'DENY',
      reason: 'pack_not_enabled',
    });
  });

  it('denies the watcher connector when the watcher feature is off', async () => {
    const h = makeDecisionHarness({
      catalog: catalog(stored({ watcher: false })),
    });
    const result = await h.service.authorize(
      h.tenantClient,
      'tenant-1',
      'agent-1',
      { ...REQUEST, toolId: MANAR_TOOL, actionId: 'manar.activity.read' },
    );
    expect(result).toMatchObject({
      decision: 'DENY',
      reason: 'watcher_disabled',
    });
  });

  it('fails closed when the catalog cannot be read', async () => {
    const h = makeDecisionHarness({
      task: { packId: 'it-helpdesk' },
      catalog: catalog(null, true),
    });
    const result = await h.service.authorize(
      h.tenantClient,
      'tenant-1',
      'agent-1',
      REQUEST,
    );
    expect(result).toMatchObject({
      decision: 'DENY',
      reason: 'enforcement_dependency_unavailable',
    });
    expect(h.openFgaCheck).not.toHaveBeenCalled();
  });
});
