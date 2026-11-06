import 'dotenv/config';
import 'reflect-metadata';
import { randomBytes, randomUUID } from 'node:crypto';
import { Client as PgClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { EnvSecretProvider } from '../src/database/env-secret-provider';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { HostConfigController } from '../src/host-mtls/host-config.controller';
import { fakeConfigService } from './support/audit-test-config';

/**
 * GET /host/v1/config `policyVersion` and `offlineReadsAllowed` against a real tenant database:
 * the token moves when something that can flip a cached ALLOW moves, and a published read rule
 * that denies or asks turns offline folder reads off.
 */
describe('host config policyVersion (e2e)', () => {
  let control: ControlPrismaService;
  let manager: TenantDatabaseManager;
  let tenantId = '';
  let databaseName = '';
  let hostId = '';
  let ctrl: HostConfigController;
  let client: Awaited<ReturnType<TenantDatabaseManager['getClient']>>;

  const poll = () =>
    ctrl.config(
      {
        hostId,
        tenantId,
        machineId: 'm-1',
        ownerSubject: null,
        status: 'APPROVED',
      } as never,
      { headers: {} } as never,
    );

  beforeAll(async () => {
    control = new ControlPrismaService(fakeConfigService());
    await control.$connect();
    manager = new TenantDatabaseManager(
      control,
      fakeConfigService(),
      new EnvSecretProvider(),
    );
    const t = await manager.provisionTenant({
      slug: `hcpv-${randomUUID().slice(0, 8)}`,
      name: 'Host config policy version',
    });
    tenantId = t.id;
    databaseName = t.databaseBinding!.databaseName;
    client = await manager.getClient(tenantId);
    const group = await client.hostGroup.create({ data: { name: 'G' } });
    hostId = (
      await client.host.create({
        data: {
          hostGroupId: group.id,
          machineId: 'm-1',
          hostname: 'LAPTOP',
          os: 'linux',
          keyType: 'SOFTWARE',
          keyFingerprint: randomBytes(32).toString('hex'),
          registeredFromIp: '10.0.0.7',
          status: 'APPROVED',
        },
      })
    ).id;
    const none = () => Promise.resolve(undefined);
    ctrl = new HostConfigController(
      { instructions: () => Promise.resolve({ unprotect: [] }) } as never,
      { isPaused: () => Promise.resolve(false) } as never,
      { doorConfig: () => Promise.resolve({}) } as never,
      manager,
      {
        features: () => Promise.resolve([]),
        vaultGrants: () => Promise.resolve([]),
      } as never,
      { config: none } as never,
      {
        forHost: () =>
          Promise.resolve({
            effective: { improveManar: false, aiTraining: false },
          }),
      } as never,
      {} as never,
      { isActive: () => Promise.resolve(false) } as never,
    );
  }, 90_000);

  afterAll(async () => {
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

  it('sends an opaque token, stable between polls, and offline reads on', async () => {
    const a = await poll();
    expect(a.policyVersion).toMatch(/^[0-9a-f]{16}$/);
    expect((await poll()).policyVersion).toBe(a.policyVersion);
    expect(a.offlineReadsAllowed).toBe(true);
  });

  it('changes when the workspace is paused and when a revoked-after-use block appears', async () => {
    const before = (await poll()).policyVersion;
    await client.workspacePause.upsert({
      where: { id: 'workspace' },
      create: { id: 'workspace', paused: true },
      update: { paused: true },
    });
    const paused = (await poll()).policyVersion;
    expect(paused).not.toBe(before);
    await client.approvalAllowGrant.create({
      data: {
        hostId,
        toolId: 'host.cursor',
        actionId: 'shell',
        resource: 'ls',
        createdBy: 'u',
        sourceId: 's',
        effect: 'BLOCK',
        expiresAt: new Date(Date.now() + 3_600_000),
      },
    });
    expect((await poll()).policyVersion).not.toBe(paused);
  });

  it('changes on a published policy and turns offline reads off for a DENY read rule', async () => {
    const before = await poll();
    const author = await client.userProfile.create({
      data: {
        keycloakSubject: randomUUID(),
        email: 'a@example.test',
        displayName: 'A',
      },
    });
    const policy = await client.policy.create({ data: { name: 'p' } });
    const mk = (version: number, status: 'DRAFT' | 'PUBLISHED') =>
      client.policyVersion.create({
        data: {
          policyId: policy.id,
          version,
          status,
          content: {
            rules: [
              {
                toolId: 'host.cursor',
                actionId: 'read',
                resourcePattern: '*',
                effect: 'DENY',
              },
            ],
          },
          contentHash: `h${version}`,
          authorId: author.id,
        },
      });
    await mk(1, 'DRAFT');
    const draft = await poll();
    expect(draft.offlineReadsAllowed).toBe(true);
    expect(draft.policyVersion).toBe(before.policyVersion);
    await mk(2, 'PUBLISHED');
    const published = await poll();
    expect(published.policyVersion).not.toBe(before.policyVersion);
    expect(published.offlineReadsAllowed).toBe(false);
  });

  it('answers 503 when the tenant database cannot be read', async () => {
    const broken = Object.create(ctrl) as HostConfigController;
    (broken as unknown as { tenants: unknown }).tenants = {
      getClient: () => Promise.reject(new Error('down')),
    };
    await expect(
      broken.config(
        { hostId, tenantId, machineId: 'm-1', status: 'APPROVED' } as never,
        { headers: {} } as never,
      ),
    ).rejects.toMatchObject({ status: 503 });
  });
});
