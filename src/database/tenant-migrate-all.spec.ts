import { describe, expect, it, vi } from 'vitest';
import { TenantDatabaseManager } from './tenant-database-manager.service';

function make(slugs: string[], failing: string[]) {
  const tenants = slugs.map((slug) => ({
    id: `id-${slug}`,
    slug,
    databaseBinding: {
      id: `b-${slug}`,
      databaseName: `tenant_${slug}`,
      secretReference: { provider: 'ENV', reference: 'X' },
    },
  }));
  const update = vi.fn().mockResolvedValue({});
  const control = {
    tenant: { findMany: vi.fn().mockResolvedValue(tenants) },
    tenantDatabaseBinding: { update },
  };
  const config = {
    get: (k: string) => (k.startsWith('TENANT_DB') ? 1000 : undefined),
  };
  const secrets = { resolve: () => Promise.resolve('postgres://u:p@h/db') };
  const m = new TenantDatabaseManager(
    control as never,
    config as never,
    secrets,
  );
  let running = 0;
  let peak = 0;
  vi.spyOn(
    m as unknown as { runTenantMigrations: (u: string) => Promise<string> },
    'runTenantMigrations',
  ).mockImplementation((url: string) => {
    running++;
    peak = Math.max(peak, running);
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        running--;
        if (failing.some((f) => url.includes(`tenant_${f}`)))
          reject(new Error('boom'));
        else resolve('v1');
      }, 5);
    });
  });
  return { m, update, peak: () => peak };
}

describe('migrateAllTenants', () => {
  it('continues past a failing tenant and reports it', async () => {
    const { m, update } = make(['a', 'b', 'c', 'd'], ['b']);
    const r = await m.migrateAllTenants(2);
    expect(r.migrated.map((x) => x.tenantId).sort()).toEqual([
      'id-a',
      'id-c',
      'id-d',
    ]);
    expect(r.failed).toEqual([{ tenantId: 'id-b', slug: 'b', error: 'boom' }]);
    expect(update).toHaveBeenCalledTimes(3);
    await m.onModuleDestroy();
  });

  it('never runs more than the concurrency bound at once', async () => {
    const { m, peak } = make(['a', 'b', 'c', 'd', 'e', 'f'], []);
    await m.migrateAllTenants(3);
    expect(peak()).toBe(3);
    await m.onModuleDestroy();
  });
});
