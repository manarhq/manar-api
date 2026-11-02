import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { Client as PgClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AuditService } from '../src/audit/audit.service';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { EnvSecretProvider } from '../src/database/env-secret-provider';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { HostToolsService } from '../src/host-coverage/host-tools.service';
import { EXPECTED_MODULES } from '../src/host-coverage/protection-status';
import { fakeConfigService } from './support/audit-test-config';

const audit = {
  recordSafely: () => Promise.resolve({}),
} as unknown as AuditService;

/** "Am I protected?" against a real tenant database: the modules column and the problem list. */
describe('Protection status (e2e)', () => {
  let control: ControlPrismaService;
  let manager: TenantDatabaseManager;
  let tools: HostToolsService;
  const provisioned: { tenantId: string; databaseName: string }[] = [];

  beforeAll(async () => {
    control = new ControlPrismaService(fakeConfigService());
    await control.$connect();
    manager = new TenantDatabaseManager(
      control,
      fakeConfigService(),
      new EnvSecretProvider(),
    );
    tools = new HostToolsService(manager, audit);
  }, 60_000);

  afterAll(async () => {
    await manager.onModuleDestroy();
    for (const { tenantId, databaseName } of provisioned) {
      const pg = new PgClient({
        connectionString: process.env.CONTROL_DATABASE_URL,
      });
      await pg.connect();
      await pg.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
      await pg.end();
      await control.tenantDatabaseBinding.deleteMany({ where: { tenantId } });
      await control.secretReference.deleteMany({ where: { tenantId } });
      await control.tenant.deleteMany({ where: { id: tenantId } });
    }
    await control.$disconnect();
  }, 60_000);

  it('goes from "add a device" to all protected, and names a stopped module', async () => {
    const t = await manager.provisionTenant({
      slug: `prot-${randomUUID().slice(0, 8)}`,
      name: 'Protection',
    });
    provisioned.push({
      tenantId: t.id,
      databaseName: t.databaseBinding!.databaseName,
    });
    expect((await tools.protection(t.id)).problems).toEqual([
      { code: 'no_device' },
    ]);

    const client = await manager.getClient(t.id);
    const group = await client.hostGroup.create({ data: { name: 'G' } });
    const host = await client.host.create({
      data: {
        hostGroupId: group.id,
        machineId: 'm-1',
        hostname: 'laptop',
        os: 'linux',
        keyType: 'SOFTWARE',
        registeredFromIp: '10.0.0.1',
        keyFingerprint: 'fp-1',
        status: 'APPROVED',
      },
    });
    expect((await tools.protection(t.id)).problems.map((p) => p.code)).toEqual([
      'device_never_synced',
    ]);

    const modules = Object.fromEntries(
      EXPECTED_MODULES.map((m) => [m, { state: 'ok' as const }]),
    );
    const ctx = { hostId: host.id, tenantId: t.id };
    const claude = {
      id: 'host.claude-code',
      name: 'Claude Code',
      protected: true,
      protectMode: 'hook' as const,
      changes: [],
    };
    await tools.report(ctx, { tools: [claude], modules });
    expect(await tools.protection(t.id)).toMatchObject({
      ok: true,
      problems: [],
    });

    await tools.report(ctx, {
      tools: [{ ...claude, protected: false, protectMode: 'none' }],
      modules: { ...modules, jail: { state: 'problem', detail: 'stopped' } },
    });
    const r = await tools.protection(t.id);
    expect(r.ok).toBe(false);
    expect(r.problems.map((p) => [p.code, p.toolName ?? p.module])).toEqual([
      ['tool_not_applied', 'Claude Code'],
      ['module_down', 'jail'],
    ]);
  }, 120_000);
});
