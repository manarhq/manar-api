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
import { HostRefusedError, HostsService } from '../src/hosts/hosts.service';
import { InstallKeysService } from '../src/hosts/install-keys.service';
import type { TpmAttestationService } from '../src/hosts/tpm/tpm-attestation.service';
import { fakeConfigService } from './support/audit-test-config';

const recorded: {
  tenantId: string;
  eventType: string;
  actor: unknown;
  data: Record<string, unknown>;
}[] = [];
const audit = {
  recordInTransaction: (
    _tx: unknown,
    tenantId: string,
    event: { eventType: string; actor: unknown; data: Record<string, unknown> },
  ) => {
    recorded.push({ tenantId, ...event });
    return Promise.resolve(() => undefined);
  },
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

  async function tenant(kind: 'PERSONAL' | 'COMPANY' = 'COMPANY') {
    const t = await manager.provisionTenant({
      slug: `re-${randomUUID().slice(0, 8)}`,
      name: 'Re',
    });
    await control.tenant.update({ where: { id: t.id }, data: { kind } });
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

    // "Remove device" retires the record, and the same code then works: within 30 days the
    // machine comes back as the same device.
    await admin.remove(
      t.client,
      t.id,
      { type: 'human', id: u.id },
      result.hostId,
    );
    const back = await install(t, again.code, 'm-2');
    expect(back.result.hostId).toBe(result.hostId);
    const revived = await t.client.host.findUniqueOrThrow({
      where: { id: result.hostId },
    });
    expect(revived.status).toBe('PENDING');
    expect(revived.removedAt).toBeNull();
  }, 60_000);

  it('removes a device with history, keeps the history, and stops the device', async () => {
    const t = await tenant();
    const u = await t.person('sub-rm');
    const actor = { type: 'human' as const, id: u.id };
    const first = await newCode(t, u.id);
    const { result } = await install(t, first.code, 'm-rm');
    const hostId = result.hostId;
    await admin.decide(t.client, t.id, actor, hostId, 'approve');
    // History of every kind that points at the device. host_approvals, approval_allow_grants
    // and host_certificates have no ON DELETE action: a hard delete failed on them in production.
    const soon = new Date(Date.now() + 3_600_000);
    const approval = (status: 'PENDING' | 'APPROVED') =>
      t.client.hostApproval.create({
        data: {
          hostId,
          toolId: 'claude-code',
          actionId: 'shell.exec',
          resource: 'rm -rf build',
          summary: 'Run a command',
          status,
          expiresAt: soon,
        },
      });
    const decided = await approval('APPROVED');
    const open = await approval('PENDING');
    const grant = await t.client.approvalAllowGrant.create({
      data: {
        hostId,
        toolId: 'claude-code',
        actionId: 'shell.exec',
        resource: 'rm -rf build',
        createdBy: 'sub-rm',
        sourceId: decided.id,
        expiresAt: soon,
      },
    });
    await t.client.hostCertificate.create({
      data: {
        hostId,
        serialNumber: `rm-${randomUUID()}`,
        notBefore: new Date(),
        notAfter: soon,
      },
    });
    await t.client.hostTool.create({
      data: { hostId, toolId: 'claude-code', name: 'Claude Code' },
    });
    await t.client.hostMcpServer.create({
      data: {
        hostId,
        toolId: 'claude-code',
        name: 'files',
        fingerprint: 'f1',
        transport: 'stdio',
      },
    });

    revokeHostCertificates.mockClear();
    recorded.length = 0;
    await admin.remove(t.client, t.id, actor, hostId);

    const host = await t.client.host.findUniqueOrThrow({
      where: { id: hostId },
    });
    expect(host.status).toBe('REMOVED');
    expect(host.removedAt).not.toBeNull();
    expect(host.hostname).toBe('LAPTOP'); // history still names the device
    expect(revokeHostCertificates).toHaveBeenCalledWith(
      expect.anything(),
      hostId,
    );
    expect(
      await t.client.hostApproval.findMany({
        where: { hostId },
        orderBy: { createdAt: 'asc' },
        select: { id: true, status: true },
      }),
    ).toEqual([
      { id: decided.id, status: 'APPROVED' },
      { id: open.id, status: 'EXPIRED' },
    ]);
    expect(
      (
        await t.client.approvalAllowGrant.findUniqueOrThrow({
          where: { id: grant.id },
        })
      ).revokedAt,
    ).not.toBeNull();
    expect(await t.client.hostTool.count({ where: { hostId } })).toBe(1);
    expect(await t.client.hostMcpServer.count({ where: { hostId } })).toBe(1);
    expect(recorded.filter((e) => e.eventType === 'host.removed')).toHaveLength(
      1,
    );

    // Hidden from the device list unless asked for; no longer counted against the plan.
    const listed = await admin.listHosts(t.client, { limit: 50 });
    expect(listed.items.map((h) => h.id)).not.toContain(hostId);
    const removed = await admin.listHosts(t.client, {
      status: 'REMOVED',
      limit: 50,
    });
    expect(removed.items.map((h) => h.id)).toEqual([hostId]);

    // A second click is harmless: no second event, revocation retried.
    await admin.remove(t.client, t.id, actor, hostId);
    expect(recorded.filter((e) => e.eventType === 'host.removed')).toHaveLength(
      1,
    );
    expect(revokeHostCertificates).toHaveBeenCalledTimes(2);

    // Approve, reject or revoke no longer apply to it.
    await expect(
      admin.decide(t.client, t.id, actor, hostId, 'approve'),
    ).rejects.toThrow();
  }, 60_000);

  it('a device that moved itself to another workspace is REMOVED as moved, certificates and standing vault grants withdrawn', async () => {
    const t = await tenant();
    const u = await t.person('sub-mv');
    const first = await newCode(t, u.id);
    const { result } = await install(t, first.code, 'm-mv');
    await admin.decide(
      t.client,
      t.id,
      { type: 'human', id: u.id },
      result.hostId,
      'approve',
    );
    const grant = await t.client.secretVaultAccess.create({
      data: {
        hostId: result.hostId,
        kind: 'aws',
        ref: 'default',
        program: 'aws',
        status: 'ALLOW_ALWAYS',
        decidedAt: new Date(),
      },
    });
    revokeHostCertificates.mockClear();
    await admin.markMoved(t.client, t.id, result.hostId);
    const host = await t.client.host.findUniqueOrThrow({
      where: { id: result.hostId },
    });
    expect(host.status).toBe('REMOVED');
    expect(host.removedReason).toBe('moved');
    expect(revokeHostCertificates).toHaveBeenCalledWith(
      expect.anything(),
      result.hostId,
    );
    expect(
      (
        await t.client.secretVaultAccess.findUniqueOrThrow({
          where: { id: grant.id },
        })
      ).withdrawnAt,
    ).not.toBeNull();
    expect(
      recorded.some(
        (e) =>
          e.tenantId === t.id &&
          e.eventType === 'host.moved' &&
          e.data.hostId === result.hostId,
      ),
    ).toBe(true);
  }, 60_000);

  it('a revive revokes every certificate the removed record still had', async () => {
    const t = await tenant();
    const u = await t.person('sub-rev');
    const first = await newCode(t, u.id);
    const { result } = await install(t, first.code, 'm-rev');
    await admin.remove(
      t.client,
      t.id,
      { type: 'human', id: u.id },
      result.hostId,
    );
    // A certificate the removal did not catch (issued while it ran).
    const stray = await t.client.hostCertificate.create({
      data: {
        hostId: result.hostId,
        serialNumber: `stray-${randomUUID()}`,
        notBefore: new Date(),
        notAfter: new Date(Date.now() + 3_600_000),
      },
    });
    const again = await newCode(t, u.id);
    const back = await install(t, again.code, 'm-rev');
    expect(back.result.hostId).toBe(result.hostId);
    expect(back.result.status).toBe('PENDING');
    const old = await t.client.hostCertificate.findUniqueOrThrow({
      where: { id: stray.id },
    });
    expect(old.revokedAt).not.toBeNull();
  }, 60_000);

  it("another person's install code cannot revive someone else's removed device", async () => {
    const t = await tenant('PERSONAL');
    const owner = await t.person('sub-own');
    const other = await t.person('sub-oth');
    const first = await newCode(t, owner.id);
    const { result } = await install(t, first.code, 'm-own');
    await admin.remove(
      t.client,
      t.id,
      { type: 'human', id: owner.id },
      result.hostId,
    );
    const theirs = await newCode(t, other.id);
    const { result: fresh } = await install(t, theirs.code, 'm-own');
    expect(fresh.hostId).not.toBe(result.hostId);
    const old = await t.client.host.findUniqueOrThrow({
      where: { id: result.hostId },
    });
    expect(old.status).toBe('REMOVED');
    expect(old.ownerSubject).toBe('sub-own');
    expect(old.machineId).toBe(`removed:${result.hostId}`);
  }, 60_000);

  it("the owner's own revive waits PENDING, never auto-approved", async () => {
    const t = await tenant('PERSONAL');
    const u = await t.person('sub-pa');
    const first = await newCode(t, u.id);
    const { result } = await install(t, first.code, 'm-pa');
    expect(result.status).toBe('APPROVED'); // a new device on a personal code
    await admin.remove(
      t.client,
      t.id,
      { type: 'human', id: u.id },
      result.hostId,
    );
    const again = await newCode(t, u.id);
    const back = await install(t, again.code, 'm-pa');
    expect(back.result.hostId).toBe(result.hostId);
    expect(back.result.status).toBe('PENDING');
  }, 60_000);

  it('a remove during registration leaves the device REMOVED with no valid certificate', async () => {
    const t = await tenant();
    const u = await t.person('sub-race');
    const first = await newCode(t, u.id);
    const { csr, result } = await install(t, first.code, 'm-race');
    const revokeSerial = vi.fn(
      (client: typeof t.client, serialNumber: string) =>
        client.hostCertificate
          .updateMany({
            where: { serialNumber, revokedAt: null },
            data: { revokedAt: new Date() },
          })
          .then(() => undefined),
    );
    // The CA stores the certificate, then the owner removes the device while it is signed.
    const racingCa = {
      ...ca,
      issueHostCertificate: async (
        client: typeof t.client,
        h: { id: string },
      ) => {
        const serialNumber = `race-${randomUUID()}`;
        await client.hostCertificate.create({
          data: {
            hostId: h.id,
            serialNumber,
            notBefore: new Date(),
            notAfter: new Date(Date.now() + 3_600_000),
          },
        });
        await admin.remove(
          t.client,
          t.id,
          { type: 'human', id: u.id },
          result.hostId,
        );
        return { certificatePem: 'CERT', caChainPem: 'CA', serialNumber };
      },
      revokeHostCertificateSerial: revokeSerial,
    } as unknown as CertificateAuthorityService;
    const racing = new HostsService(
      control,
      manager,
      keys,
      audit,
      racingCa,
      {} as TpmAttestationService,
      freeEntitlements(),
      codes,
    );
    const again = await newCode(t, u.id);
    // The same key re-installing (a new key would be its own device, untouched by this remove).
    await expect(
      racing.register({
        installKey: again.code,
        csr,
        machineId: 'm-race',
        hostname: 'LAPTOP',
        os: 'linux',
        keyType: 'SOFTWARE',
        ip: '10.0.0.7',
      }),
    ).rejects.toBeInstanceOf(HostRefusedError);
    const host = await t.client.host.findUniqueOrThrow({
      where: { id: result.hostId },
    });
    expect(host.status).toBe('REMOVED');
    expect(
      await t.client.hostCertificate.count({
        where: { hostId: result.hostId, revokedAt: null },
      }),
    ).toBe(0);
  }, 60_000);

  it('a machine removed more than 30 days ago enrols as a new device; the old record stays', async () => {
    const t = await tenant();
    const u = await t.person('sub-old');
    const first = await newCode(t, u.id);
    const { result } = await install(t, first.code, 'm-old');
    await admin.remove(
      t.client,
      t.id,
      { type: 'human', id: u.id },
      result.hostId,
    );
    await t.client.host.update({
      where: { id: result.hostId },
      data: { removedAt: new Date(Date.now() - 31 * 24 * 3_600_000) },
    });
    const again = await newCode(t, u.id);
    const { result: fresh } = await install(t, again.code, 'm-old');
    expect(fresh.hostId).not.toBe(result.hostId);
    const old = await t.client.host.findUniqueOrThrow({
      where: { id: result.hostId },
    });
    expect(old.status).toBe('REMOVED');
    expect(old.machineId).toBe(`removed:${result.hostId}`);
    expect(old.hostname).toBe('LAPTOP');
    // Learning mode's 7 days follow the machine: re-enrolling does not restart them.
    expect(old.firstApprovedAt).not.toBeNull();
    const again2 = await t.client.host.findUniqueOrThrow({
      where: { id: fresh.hostId },
    });
    expect(again2.firstApprovedAt).toEqual(old.firstApprovedAt);
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

  it("a new key for a known machine never replaces its key or certificates, the owner's own key included: it waits as a separate possible clone", async () => {
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

    revokeHostCertificates.mockClear();
    for (const who of [other, owner]) {
      const c = await newCode(t, who.id);
      const again = await install(t, c.code, 'm-5'); // a fresh key: generateAgentCsr makes a new pair
      expect(again.result.hostId).not.toBe(result.hostId);
      expect(again.result.status).toBe('PENDING');
      const clone = await t.client.host.findUniqueOrThrow({
        where: { id: again.result.hostId },
      });
      expect(clone.cloneOfHostId).toBe(result.hostId);
      expect(clone.machineId).toBe('m-5');
    }
    // The machine already in place is untouched: same key, still approved, certificates alive.
    const after = await t.client.host.findUniqueOrThrow({
      where: { id: result.hostId },
    });
    expect(after.keyFingerprint).toBe(before.keyFingerprint);
    expect(after.status).toBe('APPROVED');
    expect(after.pendingKeyFingerprint).toBeNull();
    expect(revokeHostCertificates).not.toHaveBeenCalled();
    expect(
      recorded.filter(
        (e) => e.tenantId === t.id && e.eventType === 'host.possible_clone',
      ),
    ).toHaveLength(2);
    // Each counts as a device.
    expect(
      await t.client.host.count({
        where: { machineId: 'm-5', status: { in: ['PENDING', 'APPROVED'] } },
      }),
    ).toBe(3);
  }, 120_000);

  it('a possible clone that installs again with its own key merges into its own record, not a third one', async () => {
    const t = await tenant();
    const u = await t.person('sub-twin');
    const first = await newCode(t, u.id);
    const { result } = await install(t, first.code, 'm-6');
    const second = await newCode(t, u.id);
    const clone = await install(t, second.code, 'm-6');
    const third = await newCode(t, u.id);
    const again = await install(t, third.code, 'm-6', clone.csr);
    expect(again.result.hostId).toBe(clone.result.hostId);
    expect(again.result.hostId).not.toBe(result.hostId);
    expect(await t.client.host.count({ where: { machineId: 'm-6' } })).toBe(2);
  }, 120_000);

  describe('workspace kind', () => {
    it('a personal workspace approves a device from its own Add-device code, audited', async () => {
      const t = await tenant('PERSONAL');
      const u = await t.person('sub-p1');
      const { code } = await newCode(t, u.id);
      const { result } = await install(t, code, 'p-1');
      expect(result.status).toBe('APPROVED');
      const host = await t.client.host.findUniqueOrThrow({
        where: { id: result.hostId },
      });
      expect(host.status).toBe('APPROVED');
      expect(host.approvedBy).toBe('system:personal-install-code');
      expect(host.approvedAt).not.toBeNull();
      const events = recorded.filter(
        (e) => e.tenantId === t.id && e.eventType.startsWith('host.'),
      );
      expect(events.map((e) => e.eventType)).toEqual([
        'host.registered',
        'host.approved',
      ]);
      expect(events[1]).toMatchObject({
        actor: { type: 'system', id: 'system:personal-install-code' },
        data: {
          hostId: result.hostId,
          from: 'PENDING',
          to: 'APPROVED',
          ownerSubject: 'sub-p1',
        },
      });
    }, 60_000);

    it('a re-install of a known machine with a valid code waits PENDING for the owner as its own device', async () => {
      const t = await tenant('PERSONAL');
      const u = await t.person('sub-p2');
      const first = await newCode(t, u.id);
      const { result } = await install(t, first.code, 'p-2');
      const before = await t.client.host.findUniqueOrThrow({
        where: { id: result.hostId },
      });
      expect(before.status).toBe('APPROVED');
      const again = await newCode(t, u.id);
      const second = await install(t, again.code, 'p-2'); // same machineId, a fresh key pair
      expect(second.result.status).toBe('PENDING');
      // The new key gets no decisions, tools or config until the owner approves it, and the
      // device already enrolled keeps working: nothing about it changed.
      const clone = await t.client.host.findUniqueOrThrow({
        where: { id: second.result.hostId },
      });
      expect(clone.status).toBe('PENDING');
      expect(clone.approvedBy).toBeNull();
      expect(clone.cloneOfHostId).toBe(result.hostId);
      const host = await t.client.host.findUniqueOrThrow({
        where: { id: result.hostId },
      });
      expect(host.status).toBe('APPROVED');
      expect(host.keyFingerprint).toBe(before.keyFingerprint);
      const afterEvents = recorded
        .filter((e) => e.tenantId === t.id && e.eventType.startsWith('host.'))
        .map((e) => e.eventType);
      expect(afterEvents).toEqual([
        'host.registered',
        'host.approved',
        'host.registered',
        'host.possible_clone',
      ]);
    }, 60_000);

    it('a company workspace keeps the device PENDING for a rule or an admin', async () => {
      const t = await tenant('COMPANY');
      const u = await t.person('sub-c1');
      const { code } = await newCode(t, u.id);
      const { result } = await install(t, code, 'c-1');
      expect(result.status).toBe('PENDING');
      expect(
        recorded
          .filter((e) => e.tenantId === t.id && e.eventType.startsWith('host.'))
          .map((e) => e.eventType),
      ).toEqual(['host.registered']);
    }, 60_000);

    it('a personal workspace still hits the plan device limit', async () => {
      const t = await tenant('PERSONAL');
      const u = await t.person('sub-p3');
      for (let i = 0; i < 3; i++) {
        const c = await newCode(t, u.id);
        expect((await install(t, c.code, `pcap-${i}`)).result.status).toBe(
          'APPROVED',
        );
      }
      const over = await newCode(t, u.id);
      await expect(install(t, over.code, 'pcap-9')).rejects.toBeInstanceOf(
        PlanLimitError,
      );
      expect(
        await t.client.host.count({ where: { machineId: 'pcap-9' } }),
      ).toBe(0);
    }, 120_000);
  });
});
