import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { generateAgentCsr } from '@manar/sdk-node';
import { Client as PgClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../src/audit/audit.service';
import type { CertificateAuthorityService } from '../src/agents/certificate-authority.service';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { EnvSecretProvider } from '../src/database/env-secret-provider';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { PlanLimitError } from '../src/billing/plan-limit.error';
import { freeEntitlements } from './support/free-entitlements';
import { generateInstallCode } from '../src/hosts/install-code.util';
import { InstallCodesService } from '../src/hosts/install-codes.service';
import { HostsAdminService } from '../src/hosts/hosts-admin.service';
import {
  HostRefusedError,
  HostRekeyPendingError,
  HostsService,
} from '../src/hosts/hosts.service';
import { InstallKeysService } from '../src/hosts/install-keys.service';
import type { TpmAttestationService } from '../src/hosts/tpm/tpm-attestation.service';
import { fakeConfigService } from './support/audit-test-config';

const audit = {
  recordInTransaction: () => Promise.resolve(() => undefined),
} as unknown as AuditService;
const revokeHostCertificates = vi.fn(() => Promise.resolve());
const ca = {
  assertCsrNames: () => Promise.resolve(),
  issueHostCertificate: () =>
    Promise.resolve({
      certificatePem: 'CERT',
      caChainPem: 'CA',
      serialNumber: '01',
    }),
  revokeHostCertificates,
  revokeHostCertificateSerial: () => Promise.resolve(),
} as unknown as CertificateAuthorityService;

/** Re-installing a machine, and what must not burn an install code (real databases, fake CA). */
describe('Add device re-install (e2e)', () => {
  let control: ControlPrismaService;
  let manager: TenantDatabaseManager;
  let keys: InstallKeysService;
  let codes: InstallCodesService;
  let hosts: HostsService;
  let admin: HostsAdminService;
  const provisioned: { tenantId: string; databaseName: string }[] = [];

  beforeAll(async () => {
    control = new ControlPrismaService(fakeConfigService());
    await control.$connect();
    manager = new TenantDatabaseManager(
      control,
      fakeConfigService(),
      new EnvSecretProvider(),
    );
    keys = new InstallKeysService(audit);
    codes = new InstallCodesService(control);
    const ent = freeEntitlements();
    hosts = new HostsService(
      control,
      manager,
      keys,
      audit,
      ca,
      {} as TpmAttestationService,
      ent,
      codes,
    );
    admin = new HostsAdminService(audit, ca, ent);
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
      await control.installCode.deleteMany({ where: { tenantId } });
      await control.tenantDatabaseBinding.deleteMany({ where: { tenantId } });
      await control.secretReference.deleteMany({ where: { tenantId } });
      await control.tenant.deleteMany({ where: { id: tenantId } });
    }
    await control.$disconnect();
  }, 60_000);

  async function tenant() {
    const t = await manager.provisionTenant({
      slug: `re-${randomUUID().slice(0, 8)}`,
      name: 'Re',
    });
    provisioned.push({
      tenantId: t.id,
      databaseName: t.databaseBinding!.databaseName,
    });
    const client = await manager.getClient(t.id);
    const group = await client.hostGroup.create({
      data: { name: 'My devices' },
    });
    const person = async (sub: string) =>
      client.userProfile.create({
        data: {
          keycloakSubject: sub,
          email: `${sub}@example.com`,
          displayName: sub,
        },
      });
    return { id: t.id, slug: t.slug, client, group, person };
  }

  type T = Awaited<ReturnType<typeof tenant>>;

  async function newCode(t: T, userId: string) {
    const code = generateInstallCode();
    const { key } = await keys.create(
      t.client,
      t,
      { type: 'human', id: userId },
      {
        hostGroupId: t.group.id,
        label: 'Add device',
        maxUses: 1,
        rawKey: code,
        expiresAt: new Date(Date.now() + 3_600_000),
      },
    );
    await codes.create(t.id, code, key.id, key.expiresAt!);
    return { code, key };
  }

  async function install(t: T, code: string, machineId: string, csr?: string) {
    const made =
      csr ?? (await generateAgentCsr(`host://${t.slug}/${machineId}`)).csrPem;
    return {
      csr: made,
      result: await hosts.register({
        installKey: code,
        csr: made,
        machineId,
        hostname: 'LAPTOP',
        os: 'linux',
        keyType: 'SOFTWARE',
        ip: '10.0.0.7',
      }),
    };
  }

  it('records which install key enrolled the machine', async () => {
    const t = await tenant();
    const u = await t.person('sub-1');
    const { code, key } = await newCode(t, u.id);
    const { result } = await install(t, code, 'm-1');
    const host = await t.client.host.findUniqueOrThrow({
      where: { id: result.hostId },
    });
    expect(host.installKeyId).toBe(key.id);
    expect(host.ownerSubject).toBe('sub-1');
  }, 60_000);

  it('a revoked machine is refused without burning the code', async () => {
    const t = await tenant();
    const u = await t.person('sub-2');
    const first = await newCode(t, u.id);
    const { result } = await install(t, first.code, 'm-2');
    await admin.decide(
      t.client,
      t.id,
      { type: 'human', id: u.id },
      result.hostId,
      'revoke',
    );
    const again = await newCode(t, u.id);
    await expect(install(t, again.code, 'm-2')).rejects.toBeInstanceOf(
      HostRefusedError,
    );
    const key = await t.client.installKey.findUniqueOrThrow({
      where: { id: again.key.id },
    });
    expect(key.uses).toBe(0);
    expect(await codes.find(again.code)).not.toBeNull();

    // "Remove device" deletes the record, and the same code then works.
    await admin.remove(
      t.client,
      t.id,
      { type: 'human', id: u.id },
      result.hostId,
    );
    await expect(install(t, again.code, 'm-2')).resolves.toBeDefined();
  }, 60_000);

  it('the device cap is checked before the code is used', async () => {
    const t = await tenant();
    const u = await t.person('sub-3');
    for (let i = 0; i < 3; i++) {
      const c = await newCode(t, u.id);
      await install(t, c.code, `cap-${i}`);
    }
    const over = await newCode(t, u.id);
    await expect(install(t, over.code, 'cap-9')).rejects.toBeInstanceOf(
      PlanLimitError,
    );
    const key = await t.client.installKey.findUniqueOrThrow({
      where: { id: over.key.id },
    });
    expect(key.uses).toBe(0);
  }, 120_000);

  it('the same key re-installing keeps the machine approved', async () => {
    const t = await tenant();
    const u = await t.person('sub-4');
    const first = await newCode(t, u.id);
    const { csr, result } = await install(t, first.code, 'm-4');
    await admin.decide(
      t.client,
      t.id,
      { type: 'human', id: u.id },
      result.hostId,
      'approve',
    );
    const second = await newCode(t, u.id);
    await install(t, second.code, 'm-4', csr);
    expect(
      (await t.client.host.findUniqueOrThrow({ where: { id: result.hostId } }))
        .status,
    ).toBe('APPROVED');
  }, 60_000);

  it("the owner's new key replaces the old one and waits for approval; anyone else's is a pending rekey", async () => {
    const t = await tenant();
    const owner = await t.person('sub-owner');
    const other = await t.person('sub-other');
    const first = await newCode(t, owner.id);
    const { result } = await install(t, first.code, 'm-5');
    await admin.decide(
      t.client,
      t.id,
      { type: 'human', id: owner.id },
      result.hostId,
      'approve',
    );
    const before = await t.client.host.findUniqueOrThrow({
      where: { id: result.hostId },
    });

    const stranger = await newCode(t, other.id);
    await expect(install(t, stranger.code, 'm-5')).rejects.toBeInstanceOf(
      HostRekeyPendingError,
    );
    expect(
      (await t.client.host.findUniqueOrThrow({ where: { id: result.hostId } }))
        .keyFingerprint,
    ).toBe(before.keyFingerprint);

    revokeHostCertificates.mockClear();
    const mine = await newCode(t, owner.id);
    await install(t, mine.code, 'm-5'); // a fresh key: generateAgentCsr makes a new pair
    const after = await t.client.host.findUniqueOrThrow({
      where: { id: result.hostId },
    });
    expect(after.keyFingerprint).not.toBe(before.keyFingerprint);
    expect(after.status).toBe('PENDING');
    expect(after.installKeyId).toBe(mine.key.id);
    expect(revokeHostCertificates).toHaveBeenCalledWith(
      expect.anything(),
      result.hostId,
    );
  }, 120_000);
});
