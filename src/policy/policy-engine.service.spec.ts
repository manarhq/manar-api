import { describe, expect, it } from 'vitest';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import type { ToolRegistryService } from '../tools/tool-registry.service';
import type { DataClassification } from '../common/data-classification';
import { PolicyEngine, resourcePatternMatches } from './policy-engine.service';

/** Minimal fake `tenantClient.policyVersion.findMany` — a plain in-memory row list, no real database. `PolicyEngine` only ever calls `findMany`, so nothing else needs stubbing. */
function fakeTenantClient(rows: unknown[]): TenantPrismaClient {
  return {
    policyVersion: {
      findMany: () => Promise.resolve(rows),
    },
  } as unknown as TenantPrismaClient;
}

/**
 * Phase 15a: a fake `ToolRegistryService` whose `findToolAction` returns a
 * fixed classification (or `null`, for "not registered") — mirrors
 * `risk-engine.service.spec.ts`'s identical fake for the same service.
 * Every pre-existing test in this file passes `undefined` (never
 * registered), which must keep every one of them behaving exactly as
 * before this phase — a `resourceClassification`-free rule never consults
 * this at all.
 */
function fakeToolRegistry(
  classification?: DataClassification,
): ToolRegistryService {
  return {
    findToolAction: () =>
      Promise.resolve(
        classification === undefined
          ? null
          : { tool: {}, action: { classification } },
      ),
  } as unknown as ToolRegistryService;
}

function publishedVersion(overrides: {
  id: string;
  policyId: string;
  version: number;
  content: unknown;
}) {
  return {
    id: overrides.id,
    policyId: overrides.policyId,
    version: overrides.version,
    status: 'PUBLISHED',
    content: overrides.content,
    contentHash: 'irrelevant-for-this-test',
    authorId: 'author-1',
    reason: null,
    previousVersionId: null,
    publishedAt: new Date(),
    createdAt: new Date(),
  };
}

describe('PolicyEngine', () => {
  it('ALLOWs (pass-through) when there are no published policies at all', async () => {
    const engine = new PolicyEngine(fakeToolRegistry());
    const result = await engine.evaluate(fakeTenantClient([]), 'tenant-1', {
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    });
    expect(result).toEqual({ effect: 'ALLOW' });
  });

  it('ALLOWs (pass-through) when a published policy exists but no rule matches', async () => {
    const rows = [
      publishedVersion({
        id: 'v1',
        policyId: 'p1',
        version: 1,
        content: {
          rules: [
            {
              toolId: 'iam',
              actionId: '*',
              effect: 'DENY',
              resourcePattern: '*',
            },
          ],
        },
      }),
    ];
    const engine = new PolicyEngine(fakeToolRegistry());
    const result = await engine.evaluate(fakeTenantClient(rows), 'tenant-1', {
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    });
    expect(result.effect).toBe('ALLOW');
    expect(result.matchedRule).toBeUndefined();
  });

  it('applies a matching DENY rule', async () => {
    const rows = [
      publishedVersion({
        id: 'v1',
        policyId: 'p1',
        version: 1,
        content: {
          rules: [
            {
              toolId: 'iam',
              actionId: '*',
              effect: 'DENY',
              resourcePattern: '*',
            },
          ],
        },
      }),
    ];
    const engine = new PolicyEngine(fakeToolRegistry());
    const result = await engine.evaluate(fakeTenantClient(rows), 'tenant-1', {
      toolId: 'iam',
      actionId: 'delete_user',
      resource: 'anything',
    });
    expect(result.effect).toBe('DENY');
    expect(result.policyId).toBe('p1');
  });

  it('matches a resource pattern ending in * by prefix, and only that pattern', async () => {
    const rows = [
      publishedVersion({
        id: 'v1',
        policyId: 'p1',
        version: 1,
        content: {
          rules: [
            {
              toolId: 'git',
              actionId: 'commit',
              resourcePattern: 'org/repo:main',
              effect: 'DENY',
            },
            {
              toolId: 'git',
              actionId: 'commit',
              resourcePattern: 'org/repo:*',
              effect: 'ALLOW',
            },
            {
              toolId: 'git',
              actionId: '*',
              resourcePattern: '*',
              effect: 'DENY',
            },
          ],
        },
      }),
    ];
    const engine = new PolicyEngine(fakeToolRegistry());
    const effect = async (resource: string) =>
      (
        await engine.evaluate(fakeTenantClient(rows), 'tenant-1', {
          toolId: 'git',
          actionId: 'commit',
          resource,
        })
      ).effect;
    expect(await effect('org/repo:feature/x')).toBe('ALLOW');
    expect(await effect('org/repo:main')).toBe('DENY');
    expect(await effect('org/repo')).toBe('DENY');
    expect(await effect('org/repo-other:x')).toBe('DENY');
    expect(resourcePatternMatches('*', 'x')).toBe(true);
    expect(resourcePatternMatches('a*', 'a')).toBe(true);
    expect(resourcePatternMatches('a', 'ab')).toBe(false);
  });

  it('first-match-wins within a single policy', async () => {
    const rows = [
      publishedVersion({
        id: 'v1',
        policyId: 'p1',
        version: 1,
        content: {
          rules: [
            {
              toolId: 'iam',
              actionId: 'read',
              effect: 'ALLOW',
              resourcePattern: '*',
            },
            {
              toolId: 'iam',
              actionId: '*',
              effect: 'DENY',
              resourcePattern: '*',
            },
          ],
        },
      }),
    ];
    const engine = new PolicyEngine(fakeToolRegistry());
    const result = await engine.evaluate(fakeTenantClient(rows), 'tenant-1', {
      toolId: 'iam',
      actionId: 'read',
      resource: 'anything',
    });
    expect(result.effect).toBe('ALLOW');
  });

  it('combines two published policies most-restrictive-wins (ALLOW + DENY -> DENY)', async () => {
    const rows = [
      publishedVersion({
        id: 'v1',
        policyId: 'p1',
        version: 1,
        content: {
          rules: [
            {
              toolId: 'edr',
              actionId: 'isolate_host',
              effect: 'ALLOW',
              resourcePattern: '*',
            },
          ],
        },
      }),
      publishedVersion({
        id: 'v2',
        policyId: 'p2',
        version: 1,
        content: {
          rules: [
            {
              toolId: 'edr',
              actionId: 'isolate_host',
              effect: 'DENY',
              resourcePattern: '*',
            },
          ],
        },
      }),
    ];
    const engine = new PolicyEngine(fakeToolRegistry());
    const result = await engine.evaluate(fakeTenantClient(rows), 'tenant-1', {
      toolId: 'edr',
      actionId: 'isolate_host',
      resource: 'host-1',
    });
    expect(result.effect).toBe('DENY');
  });

  it('reports EVERY policy that asks, not only the one that wins (so one cannot shadow another)', async () => {
    const ask = (id: string, policyId: string) =>
      publishedVersion({
        id,
        policyId,
        version: 1,
        content: {
          rules: [
            {
              toolId: 'edr',
              actionId: 'isolate_host',
              effect: 'APPROVAL_REQUIRED',
              resourcePattern: '*',
            },
          ],
        },
      });
    const allow = publishedVersion({
      id: 'v0',
      policyId: 'p0',
      version: 1,
      content: {
        rules: [
          {
            toolId: 'edr',
            actionId: 'isolate_host',
            effect: 'ALLOW',
            resourcePattern: '*',
          },
        ],
      },
    });
    const engine = new PolicyEngine(fakeToolRegistry());
    const result = await engine.evaluate(
      fakeTenantClient([allow, ask('v1', 'p1'), ask('v2', 'p2')]),
      'tenant-1',
      { toolId: 'edr', actionId: 'isolate_host', resource: 'host-1' },
    );
    expect(result.effect).toBe('APPROVAL_REQUIRED');
    expect(result.policyVersionId).toBe('v1'); // the one reported first...
    expect(result.asks?.map((a) => a.policyVersionId).sort()).toEqual([
      'v1',
      'v2',
    ]); // ...and the one behind it is not hidden
    // nothing asks: no list
    const none = await engine.evaluate(fakeTenantClient([allow]), 'tenant-1', {
      toolId: 'edr',
      actionId: 'isolate_host',
      resource: 'host-1',
    });
    expect(none.asks).toBeUndefined();
  });

  it('combines ALLOW + APPROVAL_REQUIRED -> APPROVAL_REQUIRED', async () => {
    const rows = [
      publishedVersion({
        id: 'v1',
        policyId: 'p1',
        version: 1,
        content: {
          rules: [
            {
              toolId: 'edr',
              actionId: 'isolate_host',
              effect: 'ALLOW',
              resourcePattern: '*',
            },
          ],
        },
      }),
      publishedVersion({
        id: 'v2',
        policyId: 'p2',
        version: 1,
        content: {
          rules: [
            {
              toolId: 'edr',
              actionId: 'isolate_host',
              effect: 'APPROVAL_REQUIRED',
              resourcePattern: '*',
            },
          ],
        },
      }),
    ];
    const engine = new PolicyEngine(fakeToolRegistry());
    const result = await engine.evaluate(fakeTenantClient(rows), 'tenant-1', {
      toolId: 'edr',
      actionId: 'isolate_host',
      resource: 'host-1',
    });
    expect(result.effect).toBe('APPROVAL_REQUIRED');
  });

  it('only consults the latest PUBLISHED version per policy, never a lower version', async () => {
    const rows = [
      publishedVersion({
        id: 'v2',
        policyId: 'p1',
        version: 2,
        content: {
          rules: [
            {
              toolId: 'fs',
              actionId: 'read',
              effect: 'ALLOW',
              resourcePattern: '*',
            },
          ],
        },
      }),
      publishedVersion({
        id: 'v1',
        policyId: 'p1',
        version: 1,
        content: {
          rules: [
            {
              toolId: 'fs',
              actionId: 'read',
              effect: 'DENY',
              resourcePattern: '*',
            },
          ],
        },
      }),
    ];
    const engine = new PolicyEngine(fakeToolRegistry());
    const result = await engine.evaluate(fakeTenantClient(rows), 'tenant-1', {
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    });
    // The rows are pre-sorted by the query's own orderBy in the real
    // implementation (policyId asc, version desc) -- this fake supplies
    // them already in that order, matching what Postgres would return.
    expect(result.effect).toBe('ALLOW');
    expect(result.policyVersionId).toBe('v2');
  });

  it('fails closed (DENY) when the action classification cannot be looked up', async () => {
    const client = {
      policyVersion: { findMany: () => Promise.resolve([]) },
    } as unknown as TenantPrismaClient;
    const engine = new PolicyEngine({
      findToolAction: () => Promise.reject(new Error('connection refused')),
    } as unknown as ToolRegistryService);
    const result = await engine.evaluate(client, 'tenant-1', {
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    });
    expect(result).toEqual({
      effect: 'DENY',
      failureReason: 'classification_lookup_failed',
    });
  });

  it('fails closed (DENY) when the database load itself throws', async () => {
    const brokenClient = {
      policyVersion: {
        findMany: () => Promise.reject(new Error('connection refused')),
      },
    } as unknown as TenantPrismaClient;

    const engine = new PolicyEngine(fakeToolRegistry());
    const result = await engine.evaluate(brokenClient, 'tenant-1', {
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    });
    expect(result.effect).toBe('DENY');
    expect(result.failureReason).toBe('policy_load_failed');
  });

  it('fails closed (DENY) when stored content fails schema validation (simulated bypass of normal validation)', async () => {
    const rows = [
      publishedVersion({
        id: 'v1',
        policyId: 'p1',
        version: 1,
        // Malformed on purpose -- "rules" missing entirely, as if a DB
        // row was written directly, bypassing PolicyContentSchema.
        content: { notRules: [] },
      }),
    ];
    const engine = new PolicyEngine(fakeToolRegistry());
    const result = await engine.evaluate(fakeTenantClient(rows), 'tenant-1', {
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    });
    expect(result.effect).toBe('DENY');
    expect(result.failureReason).toBe('policy_content_invalid');
  });

  describe('resourceClassification matching (Phase 15a, Section 53)', () => {
    it('a rule with resourceClassification only matches a request whose resolved ToolAction.classification equals it', async () => {
      const rows = [
        publishedVersion({
          id: 'v1',
          policyId: 'p1',
          version: 1,
          content: {
            rules: [
              {
                toolId: '*',
                actionId: '*',
                effect: 'APPROVAL_REQUIRED',
                resourcePattern: '*',
                resourceClassification: 'RESTRICTED',
                riskFloor: 60,
              },
            ],
          },
        }),
      ];
      const engine = new PolicyEngine(fakeToolRegistry('RESTRICTED'));
      const result = await engine.evaluate(fakeTenantClient(rows), 'tenant-1', {
        toolId: 'iam',
        actionId: 'export_users',
        resource: 'anything',
      });
      expect(result.effect).toBe('APPROVAL_REQUIRED');
      expect(result.matchedRule?.resourceClassification).toBe('RESTRICTED');
    });

    it('the same rule does NOT match when the resolved classification is different', async () => {
      const rows = [
        publishedVersion({
          id: 'v1',
          policyId: 'p1',
          version: 1,
          content: {
            rules: [
              {
                toolId: '*',
                actionId: '*',
                effect: 'DENY',
                resourcePattern: '*',
                resourceClassification: 'RESTRICTED',
              },
            ],
          },
        }),
      ];
      const engine = new PolicyEngine(fakeToolRegistry('INTERNAL'));
      const result = await engine.evaluate(fakeTenantClient(rows), 'tenant-1', {
        toolId: 'iam',
        actionId: 'export_users',
        resource: 'anything',
      });
      expect(result.effect).toBe('ALLOW');
      expect(result.matchedRule).toBeUndefined();
    });

    it('a rule with resourceClassification never matches when the {toolId, actionId} has no registered ToolAction at all (no known classification)', async () => {
      const rows = [
        publishedVersion({
          id: 'v1',
          policyId: 'p1',
          version: 1,
          content: {
            rules: [
              {
                toolId: '*',
                actionId: '*',
                effect: 'DENY',
                resourcePattern: '*',
                resourceClassification: 'RESTRICTED',
              },
            ],
          },
        }),
      ];
      // fakeToolRegistry() with no argument -> findToolAction resolves null.
      const engine = new PolicyEngine(fakeToolRegistry());
      const result = await engine.evaluate(fakeTenantClient(rows), 'tenant-1', {
        toolId: 'unregistered-tool',
        actionId: 'anything',
        resource: 'anything',
      });
      expect(result.effect).toBe('ALLOW');
      expect(result.matchedRule).toBeUndefined();
    });

    it('a rule with no resourceClassification still matches regardless of the resolved classification (unchanged pre-Phase-15a behavior)', async () => {
      const rows = [
        publishedVersion({
          id: 'v1',
          policyId: 'p1',
          version: 1,
          content: {
            rules: [
              {
                toolId: 'iam',
                actionId: '*',
                effect: 'DENY',
                resourcePattern: '*',
              },
            ],
          },
        }),
      ];
      const engine = new PolicyEngine(fakeToolRegistry('RESTRICTED'));
      const result = await engine.evaluate(fakeTenantClient(rows), 'tenant-1', {
        toolId: 'iam',
        actionId: 'delete_user',
        resource: 'anything',
      });
      expect(result.effect).toBe('DENY');
    });
  });
});
