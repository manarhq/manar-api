import 'dotenv/config';
import { generateInstallCode } from '../src/hosts/install-code.util';
import { InstallCodesService } from '../src/hosts/install-codes.service';
import { PlanLimitError } from '../src/billing/plan-limit.error';
import { freeEntitlements } from './support/free-entitlements';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient as TenantPrismaClient } from '../src/generated/tenant-client/client';
import { randomUUID } from 'node:crypto';
import { Client as PgClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AuditService } from '../src/audit/audit.service';
import { CheckpointSigner } from '../src/audit/checkpoint/checkpoint-signer';
import { KafkaPublisherService } from '../src/audit/kafka-publisher.service';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { EnvSecretProvider } from '../src/database/env-secret-provider';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import {
  InstallKeyInvalidError,
  InstallKeysService,
} from '../src/hosts/install-keys.service';
import { OpenBaoKvClient } from '../src/openbao/openbao-kv.client';
import { OpenBaoPkiClient } from '../src/openbao/openbao-pki.client';
import { CertificateAuthorityService } from '../src/agents/certificate-authority.service';
import {
  HostRefusedError,
  HostRekeyPendingError,
  HostsService,
} from '../src/hosts/hosts.service';
import {
  HostsAdminService,
  HostTransitionError,
} from '../src/hosts/hosts-admin.service';
import { TpmAttestationService } from '../src/hosts/tpm/tpm-attestation.service';
import { generateAgentCsr } from '@manar/sdk-node';
import { fakeConfigService } from './support/audit-test-config';

/** Hosts (docs/hosts.md) against a real tenant database. */
describe('Hosts (e2e)', () => {
  let control: ControlPrismaService;
  let manager: TenantDatabaseManager;
  let kafka: KafkaPublisherService;
  let audit: AuditService;
  let keys: InstallKeysService;
  let hosts: HostsService;
  let admins: HostsAdminService;
  const provisioned: { tenantId: string; databaseName: string }[] = [];
  const admin = { type: 'human' as const, id: 'user-admin' };

  beforeAll(async () => {
    control = new ControlPrismaService(fakeConfigService());
    await control.$connect();
    manager = new TenantDatabaseManager(
      control,
      fakeConfigService(),
      new EnvSecretProvider(),
    );
    kafka = new KafkaPublisherService(fakeConfigService());
    await kafka.onModuleInit();
    audit = new AuditService(
      kafka,
      new CheckpointSigner(new OpenBaoKvClient(fakeConfigService())),
    );
    keys = new InstallKeysService(audit);
    const ca = new CertificateAuthorityService(
      new OpenBaoPkiClient(fakeConfigService()),
    );
    hosts = new HostsService(
      control,
      manager,
      keys,
      audit,
      ca,
      new TpmAttestationService(control, manager, audit),
      freeEntitlements(),
      new InstallCodesService(control),
    );
    admins = new HostsAdminService(audit, ca, freeEntitlements());
  }, 60_000);

  afterAll(async () => {
    await audit.onModuleDestroy();
    await kafka.onModuleDestroy();
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

  async function tenant(label: string) {
    const t = await manager.provisionTenant({
      slug: `hosts-${label}-${randomUUID().slice(0, 6)}`,
      name: `Hosts ${label}`,
    });
    provisioned.push({
      tenantId: t.id,
      databaseName: t.databaseBinding!.databaseName,
    });
    const client = await manager.getClient(t.id);
    const group = await client.hostGroup.create({ data: { name: 'Dev' } });
    return { id: t.id, slug: t.slug, client, group };
  }

  describe('install keys', () => {
    it('a maxUses: 1 key is consumed exactly once under concurrency', async () => {
      const t = await tenant('once');
      const { raw } = await keys.create(t.client, t, admin, {
        hostGroupId: t.group.id,
        label: 'one machine',
        maxUses: 1,
      });

      const results = await Promise.allSettled(
        Array.from({ length: 10 }, () =>
          keys.consume(t.client, raw, '10.0.0.5'),
        ),
      );

      expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
      for (const r of results.filter((r) => r.status === 'rejected')) {
        expect(r.reason).toBeInstanceOf(InstallKeyInvalidError);
      }
    }, 60_000);

    it('refuses an expired, a revoked, or an out-of-range use, and never stores the raw key', async () => {
      const t = await tenant('limits');
      const expired = await keys.create(t.client, t, admin, {
        hostGroupId: t.group.id,
        label: 'expired',
        expiresAt: new Date(Date.now() - 1000),
      });
      const revoked = await keys.create(t.client, t, admin, {
        hostGroupId: t.group.id,
        label: 'revoked',
      });
      await keys.revoke(t.client, t.id, admin, revoked.key.id);
      const ranged = await keys.create(t.client, t, admin, {
        hostGroupId: t.group.id,
        label: 'office only',
        allowedCidrs: ['10.0.0.0/8'],
      });

      for (const [raw, ip] of [
        [expired.raw, '10.0.0.1'],
        [revoked.raw, '10.0.0.1'],
        [ranged.raw, '192.0.2.1'],
        ['mik_nobody_' + 'x'.repeat(43), '10.0.0.1'],
      ] as const) {
        await expect(keys.consume(t.client, raw, ip)).rejects.toBeInstanceOf(
          InstallKeyInvalidError,
        );
      }
      await expect(
        keys.consume(t.client, ranged.raw, '::ffff:10.9.9.9'),
      ).resolves.toMatchObject({ id: ranged.key.id });

      const stored = await t.client.installKey.findMany();
      expect(JSON.stringify(stored)).not.toContain(ranged.raw);
      const events = await t.client.auditEvent.findMany({
        where: { eventType: { startsWith: 'install_key.' } },
      });
      expect(events.map((e) => e.eventType).sort()).toEqual([
        'install_key.created',
        'install_key.created',
        'install_key.created',
        'install_key.revoked',
      ]);
      expect(JSON.stringify(events)).not.toContain(ranged.raw);
    }, 60_000);
  });

  describe('registration', () => {
    async function register(
      t: { slug: string },
      raw: string,
      machineId: string,
      extra: Partial<{
        hostname: string;
        ip: string;
        keyType: 'TPM' | 'SOFTWARE';
      }> = {},
    ) {
      const { csrPem } = await generateAgentCsr(
        `host://${t.slug}/${machineId}`,
      );
      const result = await hosts.register({
        installKey: raw,
        csr: csrPem,
        machineId,
        hostname: extra.hostname ?? 'DEV-LAPTOP-001',
        os: 'Windows 11 24H2',
        keyType: extra.keyType ?? 'TPM',
        ip: extra.ip ?? '10.0.0.7',
      });
      return { ...result, csr: csrPem };
    }

    it('registers a new machine as PENDING with a host certificate', async () => {
      const t = await tenant('reg');
      const { raw } = await keys.create(t.client, t, admin, {
        hostGroupId: t.group.id,
        label: 'dev',
      });

      const result = await register(t, raw, 'machine-a');

      expect(result.status).toBe('PENDING');
      expect(result.certificatePem).toContain('BEGIN CERTIFICATE');
      expect(
        await t.client.hostCertificate.count({
          where: { hostId: result.hostId },
        }),
      ).toBe(1);
      const event = await t.client.auditEvent.findFirst({
        where: { eventType: 'host.registered' },
      });
      expect(event?.data).toMatchObject({
        hostId: result.hostId,
        merged: false,
      });
    }, 60_000);

    it('auto-approves a host a rule matches, and leaves others pending', async () => {
      const t = await tenant('rule');
      await t.client.hostApprovalRule.create({
        data: {
          hostGroupId: t.group.id,
          hostnamePattern: 'dev-*',
          cidrs: ['10.0.0.0/8'],
        },
      });
      const { raw } = await keys.create(t.client, t, admin, {
        hostGroupId: t.group.id,
        label: 'dev',
      });

      expect((await register(t, raw, 'm1')).status).toBe('APPROVED');
      expect((await register(t, raw, 'm2', { hostname: 'SRV-9' })).status).toBe(
        'PENDING',
      );
      expect((await register(t, raw, 'm3', { ip: '192.0.2.4' })).status).toBe(
        'PENDING',
      );
    }, 60_000);

    it('merges a re-registering machine (VDI) and keeps its approval', async () => {
      const t = await tenant('merge');
      const { raw } = await keys.create(t.client, t, admin, {
        hostGroupId: t.group.id,
        label: 'vdi',
      });
      const first = await register(t, raw, 'golden-1');
      await t.client.host.update({
        where: { id: first.hostId },
        data: { status: 'APPROVED' },
      });

      // The same machine key (a persistent VDI identity) re-registering.
      const second = await hosts.register({
        installKey: raw,
        csr: first.csr,
        machineId: 'golden-1',
        hostname: 'VDI-POOL-17',
        os: 'Windows 11 24H2',
        keyType: 'TPM',
        ip: '10.0.0.7',
      });

      expect(second.hostId).toBe(first.hostId);
      expect(second.status).toBe('APPROVED');
      expect(
        await t.client.hostCertificate.count({
          where: { hostId: first.hostId },
        }),
      ).toBe(2);
      expect(
        (await t.client.host.findUniqueOrThrow({ where: { id: first.hostId } }))
          .hostname,
      ).toBe('VDI-POOL-17');
    }, 60_000);

    it('a different key for a known machine never touches it: the key becomes its own PENDING host (possible clone)', async () => {
      const t = await tenant('clone');
      const { raw } = await keys.create(t.client, t, admin, {
        hostGroupId: t.group.id,
        label: 'dev',
      });
      const first = await register(t, raw, 'laptop-7');
      await t.client.host.update({
        where: { id: first.hostId },
        data: { status: 'APPROVED' },
      });

      // register() makes a fresh key pair each call: a different key.
      const second = await register(t, raw, 'laptop-7');
      expect(second.hostId).not.toBe(first.hostId);
      expect(second.status).toBe('PENDING');

      // Nothing changed for the machine already in place: same key, approved, its certificate valid.
      const host = await t.client.host.findUniqueOrThrow({
        where: { id: first.hostId },
      });
      expect(host.status).toBe('APPROVED');
      expect(host.pendingKeyFingerprint).toBeNull();
      expect(
        await t.client.hostCertificate.count({
          where: { hostId: first.hostId, revokedAt: null },
        }),
      ).toBe(1);
      const clone = await t.client.host.findUniqueOrThrow({
        where: { id: second.hostId },
      });
      expect(clone.cloneOfHostId).toBe(first.hostId);
      expect(
        await t.client.auditEvent.count({
          where: { eventType: 'host.possible_clone' },
        }),
      ).toBe(1);

      // An admin approves the clone: two devices, each with its own valid certificate.
      await admins.decide(t.client, t.id, admin, second.hostId, 'approve');
      for (const id of [first.hostId, second.hostId]) {
        expect(
          await t.client.hostCertificate.count({
            where: { hostId: id, revokedAt: null },
          }),
        ).toBe(1);
      }
    }, 60_000);

    it('a second rekey (another group) cannot replace a pending one; revoking clears it', async () => {
      const t = await tenant('rekey2');
      const ops = await t.client.hostGroup.create({ data: { name: 'Ops' } });
      const qa = await t.client.hostGroup.create({ data: { name: 'QA' } });
      const { raw } = await keys.create(t.client, t, admin, {
        hostGroupId: t.group.id,
        label: 'dev',
      });
      const first = await register(t, raw, 'laptop-8');
      const again = (groupId: string) =>
        keys
          .create(t.client, t, admin, { hostGroupId: groupId, label: 'x' })
          .then(({ raw: k }) =>
            hosts.register({
              installKey: k,
              csr: first.csr,
              machineId: 'laptop-8',
              hostname: 'L8',
              os: 'Linux',
              keyType: 'SOFTWARE',
              ip: '10.0.0.7',
            }),
          );
      await expect(again(ops.id)).rejects.toBeInstanceOf(HostRekeyPendingError);
      const pending = (
        await t.client.host.findUniqueOrThrow({ where: { id: first.hostId } })
      ).pendingHostGroupId;
      expect(pending).toBe(ops.id);
      await expect(again(qa.id)).rejects.toBeInstanceOf(HostRekeyPendingError);
      expect(
        (await t.client.host.findUniqueOrThrow({ where: { id: first.hostId } }))
          .pendingHostGroupId,
      ).toBe(ops.id);
      // Both attempts are on record, the second marked as conflicting.
      const requested = await t.client.auditEvent.findMany({
        where: { eventType: 'host.rekey_requested' },
        orderBy: { timestamp: 'asc' },
      });
      expect(requested).toHaveLength(2);
      expect(
        requested.map(
          (e) =>
            (e.data as { conflictsWithPending: boolean }).conflictsWithPending,
        ),
      ).toEqual([false, true]);

      await admins.decide(t.client, t.id, admin, first.hostId, 'revoke');
      const revoked = await t.client.host.findUniqueOrThrow({
        where: { id: first.hostId },
      });
      expect(revoked.pendingHostGroupId).toBeNull();
      await expect(
        admins.decide(t.client, t.id, admin, first.hostId, 'approve', {
          keyFingerprint: revoked.keyFingerprint,
        }),
      ).rejects.toBeInstanceOf(HostTransitionError);
    }, 60_000);

    it('a certificate issued while the host was being revoked is revoked at once', async () => {
      const t = await tenant('race');
      const { raw } = await keys.create(t.client, t, admin, {
        hostGroupId: t.group.id,
        label: 'dev',
      });
      const first = await register(t, raw, 'racer');
      // A CA that lets an admin revoke the host in the middle of issuance.
      const racingCa = new (class extends CertificateAuthorityService {
        override async issueHostCertificate(
          ...args: Parameters<
            CertificateAuthorityService['issueHostCertificate']
          >
        ) {
          await t.client.host.update({
            where: { id: first.hostId },
            data: { status: 'REVOKED' },
          });
          return super.issueHostCertificate(...args);
        }
      })(new OpenBaoPkiClient(fakeConfigService()));
      const racingHosts = new HostsService(
        control,
        manager,
        keys,
        audit,
        racingCa,
        new TpmAttestationService(control, manager, audit),
        freeEntitlements(),
        new InstallCodesService(control),
      );

      await expect(
        racingHosts.register({
          installKey: raw,
          csr: first.csr,
          machineId: 'racer',
          hostname: 'RACER',
          os: 'Linux',
          keyType: 'TPM',
          ip: '10.0.0.7',
        }),
      ).rejects.toBeInstanceOf(HostRefusedError);
      expect(
        await t.client.hostCertificate.count({
          where: { hostId: first.hostId, revokedAt: null },
        }),
      ).toBe(1); // only the first registration's
    }, 60_000);

    it('an approve racing a revoke never brings the host back', async () => {
      const t = await tenant('decide-race');
      for (let wave = 0; wave < 20; wave += 1) {
        const host = await t.client.host.create({
          data: {
            hostGroupId: t.group.id,
            machineId: `race-${wave}`,
            hostname: `RACE-${wave}`,
            os: 'Linux',
            keyType: 'TPM',
            keyFingerprint: 'f'.repeat(64),
            registeredFromIp: '10.0.0.7',
          },
        });
        const [, revoked] = await Promise.allSettled([
          admins.decide(t.client, t.id, admin, host.id, 'approve'),
          admins.decide(t.client, t.id, admin, host.id, 'revoke'),
        ]);
        const after = await t.client.host.findUniqueOrThrow({
          where: { id: host.id },
        });
        if (revoked.status === 'fulfilled')
          expect(after.status).toBe('REVOKED');
      }
    }, 120_000);

    it('an expired key stays expired whatever the database session time zone', async () => {
      const t = await tenant('tz');
      const { key, raw } = await keys.create(t.client, t, admin, {
        hostGroupId: t.group.id,
        label: 'expired',
        expiresAt: new Date(Date.now() - 60_000),
      });
      const binding = await control.tenantDatabaseBinding.findFirstOrThrow({
        where: { tenantId: t.id },
      });
      const url = new URL(process.env.TENANT_DB_BASE_URL!);
      url.pathname = `/${binding.databaseName}`;
      url.searchParams.set('options', '-c timezone=America/Los_Angeles');
      const behind = new TenantPrismaClient({
        adapter: new PrismaPg({ connectionString: url.toString() }),
      });
      try {
        await expect(
          keys.consume(behind, raw, '10.0.0.7'),
        ).rejects.toBeInstanceOf(InstallKeyInvalidError);
        expect(
          (
            await t.client.installKey.findUniqueOrThrow({
              where: { id: key.id },
            })
          ).uses,
        ).toBe(0);
      } finally {
        await behind.$disconnect();
      }
    }, 60_000);

    it('a key from another group cannot move a known machine by itself', async () => {
      const t = await tenant('move');
      const other = await t.client.hostGroup.create({ data: { name: 'Ops' } });
      const devKey = await keys.create(t.client, t, admin, {
        hostGroupId: t.group.id,
        label: 'dev',
      });
      const opsKey = await keys.create(t.client, t, admin, {
        hostGroupId: other.id,
        label: 'ops',
      });
      const first = await register(t, devKey.raw, 'box-9');

      await expect(
        hosts.register({
          installKey: opsKey.raw,
          csr: first.csr,
          machineId: 'box-9',
          hostname: 'BOX-9',
          os: 'Linux',
          keyType: 'TPM',
          ip: '10.0.0.7',
        }),
      ).rejects.toBeInstanceOf(HostRekeyPendingError);
      const host = await t.client.host.findUniqueOrThrow({
        where: { id: first.hostId },
      });
      expect(host.hostGroupId).toBe(t.group.id);
      expect(host.pendingHostGroupId).toBe(other.id);
    }, 60_000);

    it('a revoked machine stays revoked in every group of the tenant', async () => {
      const t = await tenant('groups');
      const other = await t.client.hostGroup.create({ data: { name: 'Ops' } });
      const devKey = await keys.create(t.client, t, admin, {
        hostGroupId: t.group.id,
        label: 'dev',
      });
      const opsKey = await keys.create(t.client, t, admin, {
        hostGroupId: other.id,
        label: 'ops',
      });
      const first = await register(t, devKey.raw, 'same-box');
      await t.client.host.update({
        where: { id: first.hostId },
        data: { status: 'REVOKED' },
      });

      await expect(register(t, opsKey.raw, 'same-box')).rejects.toBeInstanceOf(
        HostRefusedError,
      );
      expect(await t.client.host.count()).toBe(1);
    }, 60_000);

    it('a revoked machine stays revoked and gets no certificate', async () => {
      const t = await tenant('revoked');
      const { raw } = await keys.create(t.client, t, admin, {
        hostGroupId: t.group.id,
        label: 'dev',
      });
      const first = await register(t, raw, 'gone');
      await t.client.host.update({
        where: { id: first.hostId },
        data: { status: 'REVOKED' },
      });

      await expect(register(t, raw, 'gone')).rejects.toBeInstanceOf(
        HostRefusedError,
      );
      expect(
        await t.client.hostCertificate.count({
          where: { hostId: first.hostId },
        }),
      ).toBe(1);
    }, 60_000);

    it("a key can't be used under another tenant's name", async () => {
      const a = await tenant('ta');
      const b = await tenant('tb');
      const { raw } = await keys.create(a.client, a, admin, {
        hostGroupId: a.group.id,
        label: 'a',
      });
      const forged = raw.replace(`mik_${a.slug}_`, `mik_${b.slug}_`);

      await expect(register(b, forged, 'x')).rejects.toBeInstanceOf(
        InstallKeyInvalidError,
      );
      expect(await b.client.host.count()).toBe(0);
    }, 60_000);

    it('refuses a CSR that names another machine', async () => {
      const t = await tenant('csr');
      const { raw } = await keys.create(t.client, t, admin, {
        hostGroupId: t.group.id,
        label: 'dev',
      });
      const { csrPem } = await generateAgentCsr(
        `host://${t.slug}/someone-else`,
      );
      await expect(
        hosts.register({
          installKey: raw,
          csr: csrPem,
          machineId: 'me',
          hostname: 'h',
          os: 'Linux',
          keyType: 'SOFTWARE',
          ip: '10.0.0.1',
        }),
      ).rejects.toThrow(/Subject Alternative Name/);
      expect(await t.client.host.count()).toBe(0);
    }, 60_000);
  });
  describe('Add device short code', () => {
    it('registers with the code once, records the owner, and deletes the code row', async () => {
      const t = await tenant('code');
      const user = await t.client.userProfile.create({
        data: {
          keycloakSubject: 'sub-owner',
          email: 'o@example.com',
          displayName: 'O',
        },
      });
      const code = generateInstallCode();
      const { key } = await keys.create(
        t.client,
        t,
        { type: 'human', id: user.id },
        {
          hostGroupId: t.group.id,
          label: 'Add device',
          maxUses: 1,
          rawKey: code,
        },
      );
      const installCodes = new InstallCodesService(control);
      await installCodes.create(
        t.id,
        code,
        key.id,
        new Date(Date.now() + 3_600_000),
      );
      const { csrPem } = await generateAgentCsr(`host://${t.slug}/code-1`);
      const body = {
        installKey: code,
        csr: csrPem,
        machineId: 'code-1',
        hostname: 'LAPTOP',
        os: 'linux',
        keyType: 'SOFTWARE' as const,
        ip: '10.0.0.7',
      };
      const done = await hosts.register(body);
      expect(done.status).toBe('PENDING');
      const host = await t.client.host.findUniqueOrThrow({
        where: { id: done.hostId },
      });
      expect(host.ownerSubject).toBe('sub-owner');
      expect(await installCodes.find(code)).toBeNull();
      await expect(hosts.register(body)).rejects.toBeInstanceOf(
        InstallKeyInvalidError,
      );
    }, 60_000);

    it("a code cannot register into another tenant: the CSR must carry the code's tenant", async () => {
      const a = await tenant('code-a');
      const b = await tenant('code-b');
      const code = generateInstallCode();
      const { key } = await keys.create(a.client, a, admin, {
        hostGroupId: a.group.id,
        label: 'x',
        maxUses: 1,
        rawKey: code,
      });
      await new InstallCodesService(control).create(
        a.id,
        code,
        key.id,
        new Date(Date.now() + 3_600_000),
      );
      const { csrPem } = await generateAgentCsr(`host://${b.slug}/m-1`);
      await expect(
        hosts.register({
          installKey: code,
          csr: csrPem,
          machineId: 'm-1',
          hostname: 'X',
          os: 'linux',
          keyType: 'SOFTWARE',
          ip: '10.0.0.7',
        }),
      ).rejects.toThrow(/Subject Alternative Name/);
      expect(await b.client.host.count()).toBe(0);
    }, 60_000);
  });

  describe('device cap', () => {
    it('lets exactly N of N+1 parallel registrations through (free plan: 3 devices)', async () => {
      const t = await tenant('cap');
      const attempts = await Promise.allSettled(
        Array.from({ length: 4 }, async (_, i) => {
          const { raw } = await keys.create(t.client, t, admin, {
            hostGroupId: t.group.id,
            label: `device ${i}`,
            maxUses: 1,
          });
          const machineId = `cap-${i}`;
          const { csrPem } = await generateAgentCsr(
            `host://${t.slug}/${machineId}`,
          );
          return hosts.register({
            installKey: raw,
            csr: csrPem,
            machineId,
            hostname: `PC-${i}`,
            os: 'linux',
            keyType: 'SOFTWARE',
            ip: '10.0.0.7',
          });
        }),
      );
      expect(attempts.filter((r) => r.status === 'fulfilled')).toHaveLength(3);
      const failed = attempts.filter((r) => r.status === 'rejected');
      expect(failed).toHaveLength(1);
      expect(failed[0]!.reason).toBeInstanceOf(PlanLimitError);
      expect(await t.client.host.count()).toBe(3);
    }, 60_000);
  });
});
