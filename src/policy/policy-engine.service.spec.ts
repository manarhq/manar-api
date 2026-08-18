import { describe, expect, it } from 'vitest';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { PolicyEngine } from './policy-engine.service';

/** Minimal fake `tenantClient.policyVersion.findMany` — a plain in-memory row list, no real database. `PolicyEngine` only ever calls `findMany`, so nothing else needs stubbing. */
function fakeTenantClient(rows: unknown[]): TenantPrismaClient {
  return {
    policyVersion: {
      findMany: () => Promise.resolve(rows),
    },
  } as unknown as TenantPrismaClient;
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
    const engine = new PolicyEngine();
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
    const engine = new PolicyEngine();
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
    const engine = new PolicyEngine();
    const result = await engine.evaluate(fakeTenantClient(rows), 'tenant-1', {
      toolId: 'iam',
      actionId: 'delete_user',
      resource: 'anything',
    });
    expect(result.effect).toBe('DENY');
    expect(result.policyId).toBe('p1');
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
    const engine = new PolicyEngine();
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
    const engine = new PolicyEngine();
    const result = await engine.evaluate(fakeTenantClient(rows), 'tenant-1', {
      toolId: 'edr',
      actionId: 'isolate_host',
      resource: 'host-1',
    });
    expect(result.effect).toBe('DENY');
  });

  it('combines ALLOW + REQUIRE_APPROVAL -> REQUIRE_APPROVAL', async () => {
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
              effect: 'REQUIRE_APPROVAL',
              resourcePattern: '*',
            },
          ],
        },
      }),
    ];
    const engine = new PolicyEngine();
    const result = await engine.evaluate(fakeTenantClient(rows), 'tenant-1', {
      toolId: 'edr',
      actionId: 'isolate_host',
      resource: 'host-1',
    });
    expect(result.effect).toBe('REQUIRE_APPROVAL');
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
    const engine = new PolicyEngine();
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

  it('fails closed (DENY) when the database load itself throws', async () => {
    const brokenClient = {
      policyVersion: {
        findMany: () => Promise.reject(new Error('connection refused')),
      },
    } as unknown as TenantPrismaClient;

    const engine = new PolicyEngine();
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
    const engine = new PolicyEngine();
    const result = await engine.evaluate(fakeTenantClient(rows), 'tenant-1', {
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    });
    expect(result.effect).toBe('DENY');
    expect(result.failureReason).toBe('policy_content_invalid');
  });
});
