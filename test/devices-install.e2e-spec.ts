import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { Client as PgClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AuthContext } from '../src/auth/auth-context';
import type { AuditService } from '../src/audit/audit.service';
import type { CertificateAuthorityService } from '../src/agents/certificate-authority.service';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { EnvSecretProvider } from '../src/database/env-secret-provider';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { DevicesService } from '../src/devices/devices.service';
import {
  EntitlementsService,
  PlanLimitError,
} from '../src/entitlements/entitlements.service';
import { HostsAdminService } from '../src/hosts/hosts-admin.service';
import { InstallCodesService } from '../src/hosts/install-codes.service';
import {
  InstallKeyInvalidError,
  InstallKeysService,
} from '../src/hosts/install-keys.service';
import { fakeConfigService } from './support/audit-test-config';

// Audit and the CA are not what is under test here; the audit stub just lets transactions run.
const audit = {
  recordInTransaction: () => Promise.resolve(() => undefined),
} as unknown as AuditService;
const ca = {
  revokeHostCertificates: () => Promise.resolve(),
} as unknown as CertificateAuthorityService;

/** Add device codes and the device cap, against real control and tenant databases. */
describe('Add device (e2e)', () => {
  let control: ControlPrismaService;
  let manager: TenantDatabaseManager;
  let keys: InstallKeysService;
  let codes: InstallCodesService;
  let devices: DevicesService;
  const provisioned: { tenantId: string; databaseName: string }[] = [];

  beforeAll(async () => {
    process.env.MANAR_STUB_ENFORCE_PLAN_LIMITS = 'true';
    control = new ControlPrismaService(fakeConfigService());
    await control.$connect();
    manager = new TenantDatabaseManager(
      control,
      fakeConfigService(),
      new EnvSecretProvider(),
    );
    keys = new InstallKeysService(audit);
    codes = new InstallCodesService(control);
    devices = new DevicesService(
      manager,
      keys,
      codes,
      new EntitlementsService(),
      fakeConfigService(),
    );
  }, 60_000);

  afterAll(async () => {
    delete process.env.MANAR_STUB_ENFORCE_PLAN_LIMITS;
    await manager.onModuleDestroy();
    for (const { tenantId, databaseName } of provisioned) {
      const pg = new PgClient({
        connectionString: process.env.CONTROL_DATABASE_URL,
      });
      await pg.connect();
      await pg.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
      await pg.end();
      await control.installCode.deleteMany({ where: { tenantId } });
      await control.tenantDatabaseBinding.deleteMany({ where: { tenantId } });
      await control.secretReference.deleteMany({ where: { tenantId } });
      await control.tenant.deleteMany({ where: { id: tenantId } });
    }
    await control.$disconnect();
  }, 60_000);

  async function tenant() {
    const t = await manager.provisionTenant({
      slug: `dev-${randomUUID().slice(0, 8)}`,
      name: 'Devices',
    });
    provisioned.push({
      tenantId: t.id,
      databaseName: t.databaseBinding!.databaseName,
    });
    const client = await manager.getClient(t.id);
    const user = await client.userProfile.create({
      data: {
        keycloakSubject: `sub-${randomUUID()}`,
        email: 'a@example.com',
        displayName: 'A',
      },
    });
    const auth = {
      tenant: { id: t.id, slug: t.slug },
      user: {
        id: user.id,
        keycloakSubject: user.keycloakSubject,
        email: user.email,
        displayName: 'A',
      },
      roles: ['TENANT_OWNER'],
    } as unknown as AuthContext;
    return { id: t.id, slug: t.slug, client, auth };
  }

  it('an install code lasts an hour, works once, and leaves no key at rest', async () => {
    const t = await tenant();
    const made = await devices.createInstallCode(t.auth);
    expect(made.code).toMatch(/^[A-HJKMNP-Z2-9]{10}$/);
    const ttl = Date.parse(made.expiresAt) - Date.now();
    expect(ttl).toBeGreaterThan(59 * 60_000);
    expect(ttl).toBeLessThanOrEqual(60 * 60_000);
    expect(made.windows).toContain(`/i/${made.code}`);
    expect(made.linux).toContain(`/i/${made.code}.sh`);

    // The control DB holds a hash, never the code or a key.
    const rows = await control.installCode.findMany({
      where: { tenantId: t.id },
    });
    expect(rows).toHaveLength(1);
    expect(JSON.stringify(rows)).not.toContain(made.code);
    expect(rows[0]!.codeHash).toMatch(/^[0-9a-f]{64}$/);

    // Looking it up twice (the script being fetched twice) changes nothing.
    const first = await codes.find(made.code);
    const second = await codes.find(made.code.toLowerCase());
    expect(first).toEqual(second);
    expect(first?.tenantSlug).toBe(t.slug);
    const key = await t.client.installKey.findUniqueOrThrow({
      where: { id: first!.installKeyId },
    });
    expect(key.maxUses).toBe(1);
    expect(key.uses).toBe(0);

    // Registration uses the code once.
    await keys.consume(t.client, made.code, '10.0.0.1');
    await expect(
      keys.consume(t.client, made.code, '10.0.0.1'),
    ).rejects.toBeInstanceOf(InstallKeyInvalidError);
  }, 120_000);

  it('an expired code resolves to nothing and its row is purged at once', async () => {
    const t = await tenant();
    const made = await devices.createInstallCode(t.auth);
    await control.installCode.updateMany({
      where: { tenantId: t.id },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    expect(await codes.find(made.code)).toBeNull();
    expect(await control.installCode.count({ where: { tenantId: t.id } })).toBe(
      0,
    );
  }, 120_000);

  it('revoking the key removes its code; using the code removes it too', async () => {
    const t = await tenant();
    const made = await devices.createInstallCode(t.auth);
    const found = (await codes.find(made.code))!;
    await keys.revoke(
      t.client,
      t.id,
      { type: 'human', id: 'u' },
      found.installKeyId,
    );
    await codes.deleteByKeyId(found.installKeyId);
    expect(await codes.find(made.code)).toBeNull();

    const again = await devices.createInstallCode(t.auth);
    await codes.deleteByCode(again.code);
    expect(await codes.find(again.code)).toBeNull();
  }, 120_000);

  it('Add device is refused at the plan cap with plan_limit_reached', async () => {
    const t = await tenant();
    const group = await t.client.hostGroup.create({ data: { name: 'G' } });
    for (let i = 0; i < 3; i++) {
      await t.client.host.create({
        data: {
          hostGroupId: group.id,
          machineId: `m-${i}`,
          hostname: `pc-${i}`,
          os: 'linux',
          keyType: 'SOFTWARE',
          registeredFromIp: '10.0.0.1',
          keyFingerprint: `fp-${i}`,
        },
      });
    }
    await expect(devices.createInstallCode(t.auth)).rejects.toBeInstanceOf(
      PlanLimitError,
    );
  }, 120_000);

  it('re-approving a rejected host at the cap is refused with plan_limit_reached', async () => {
    const t = await tenant();
    const group = await t.client.hostGroup.create({ data: { name: 'G' } });
    const make = (i: number, status: 'PENDING' | 'REJECTED') =>
      t.client.host.create({
        data: {
          hostGroupId: group.id,
          machineId: `m-${i}`,
          hostname: `pc-${i}`,
          os: 'linux',
          keyType: 'SOFTWARE',
          registeredFromIp: '10.0.0.1',
          keyFingerprint: `fp-${i}`,
          status,
        },
      });
    for (let i = 0; i < 3; i++) await make(i, 'PENDING');
    const rejected = await make(9, 'REJECTED');
    const admin = new HostsAdminService(audit, ca, new EntitlementsService());
    const actor = { type: 'human' as const, id: 'u' };
    const err = await admin
      .decide(t.client, t.id, actor, rejected.id, 'approve')
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PlanLimitError);
    expect((err as PlanLimitError).toHttp().getResponse()).toMatchObject({
      code: 'plan_limit_reached',
      limit: 'devices',
    });
    expect(
      (await t.client.host.findUniqueOrThrow({ where: { id: rejected.id } }))
        .status,
    ).toBe('REJECTED');

    // Room again: the same re-approval goes through.
    await t.client.host.updateMany({
      where: { status: 'PENDING', machineId: 'm-0' },
      data: { status: 'REVOKED' },
    });
    const ok = await admin.decide(
      t.client,
      t.id,
      actor,
      rejected.id,
      'approve',
    );
    expect(ok.status).toBe('APPROVED');
  }, 120_000);
});
