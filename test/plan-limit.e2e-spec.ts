import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { Client as PgClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { EnvSecretProvider } from '../src/database/env-secret-provider';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import {
  EntitlementsService,
  PlanLimitError,
} from '../src/entitlements/entitlements.service';
import { fakeConfigService } from './support/audit-test-config';

/** The device cap is enforced under a lock: N+1 parallel adds let exactly N through. */
describe('plan limit under concurrency (e2e)', () => {
  let control: ControlPrismaService;
  let manager: TenantDatabaseManager;
  let tenantId = '';
  let databaseName = '';

  beforeAll(async () => {
    process.env.MANAR_STUB_ENFORCE_PLAN_LIMITS = 'true';
    control = new ControlPrismaService(fakeConfigService());
    await control.$connect();
    manager = new TenantDatabaseManager(
      control,
      fakeConfigService(),
      new EnvSecretProvider(),
    );
    const t = await manager.provisionTenant({
      slug: `cap-${randomUUID().slice(0, 8)}`,
      name: 'Cap',
    });
    tenantId = t.id;
    databaseName = t.databaseBinding!.databaseName;
  }, 120_000);

  afterAll(async () => {
    delete process.env.MANAR_STUB_ENFORCE_PLAN_LIMITS;
    await manager.onModuleDestroy();
    const pg = new PgClient({
      connectionString: process.env.CONTROL_DATABASE_URL,
    });
    await pg.connect();
    await pg.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
    await pg.end();
    await control.tenantDatabaseBinding.deleteMany({ where: { tenantId } });
    await control.secretReference.deleteMany({ where: { tenantId } });
    await control.tenant.deleteMany({ where: { id: tenantId } });
    await control.$disconnect();
  }, 60_000);

  it('exactly 3 of 4 parallel adds succeed on the free plan', async () => {
    const client = await manager.getClient(tenantId);
    const group = await client.hostGroup.create({ data: { name: 'Dev' } });
    const entitlements = new EntitlementsService();
    const results = await Promise.allSettled(
      Array.from({ length: 4 }, (_, i) =>
        entitlements.withinLimit(
          tenantId,
          'devices',
          client,
          (tx) => tx.host.count(),
          (tx) =>
            tx.host.create({
              data: {
                hostGroupId: group.id,
                machineId: `m-${i}`,
                hostname: `pc-${i}`,
                os: 'linux',
                keyType: 'SOFTWARE',
                registeredFromIp: '10.0.0.1',
                keyFingerprint: `fp-${i}`,
              },
            }),
        ),
      ),
    );
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(3);
    const failed = results.filter((r) => r.status === 'rejected');
    expect(failed).toHaveLength(1);
    expect(failed[0]!.reason).toBeInstanceOf(PlanLimitError);
    expect(await client.host.count()).toBe(3);
  }, 60_000);
});
