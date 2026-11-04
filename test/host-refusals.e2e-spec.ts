import 'dotenv/config';
import 'reflect-metadata';
import { randomBytes, randomUUID } from 'node:crypto';
import type { ExecutionContext, HttpException } from '@nestjs/common';
import * as x509 from '@peculiar/x509';
import { Client as PgClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { normalizeSerialNumber } from '../src/agents/serial-number.util';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { EnvSecretProvider } from '../src/database/env-secret-provider';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { HostAuthGuard } from '../src/host-mtls/host-auth.guard';
import { SecretAlertBus } from '../src/secrets/secret-alert-bus';
import { SecretsService } from '../src/secrets/secrets.service';
import type { RequestWithHost } from '../src/host-mtls/host-context';
import { fakeConfigService } from './support/audit-test-config';

const alg = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };

/**
 * What a genuine device certificate is told when Manar will not serve it (real databases). Only
 * 410 device_removed tells a device to give the tools back; every other refusal is 423, which
 * every manar-edge (0.1.6 included) reads as "cannot ask: deny, keep the hooks".
 */
describe('host refusals (e2e)', () => {
  let control: ControlPrismaService;
  let manager: TenantDatabaseManager;
  let guard: HostAuthGuard;
  const provisioned: { tenantId: string; databaseName: string }[] = [];

  beforeAll(async () => {
    x509.cryptoProvider.set(crypto);
    control = new ControlPrismaService(fakeConfigService());
    await control.$connect();
    manager = new TenantDatabaseManager(
      control,
      fakeConfigService(),
      new EnvSecretProvider(),
    );
    guard = new HostAuthGuard(control, manager);
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

  async function device(machineId = 'm-1') {
    const t = await manager.provisionTenant({
      slug: `ref-${randomUUID().slice(0, 8)}`,
      name: 'Refusals',
    });
    provisioned.push({
      tenantId: t.id,
      databaseName: t.databaseBinding!.databaseName,
    });
    const client = await manager.getClient(t.id);
    const group = await client.hostGroup.create({ data: { name: 'G' } });
    const cert = async (hostId: string) => {
      const serial = randomBytes(8).toString('hex').toUpperCase();
      const keys = await crypto.subtle.generateKey(alg, true, [
        'sign',
        'verify',
      ]);
      const c = await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: serial,
        name: 'CN=host',
        notBefore: new Date(Date.now() - 60_000),
        notAfter: new Date(Date.now() + 3_600_000),
        signingAlgorithm: alg,
        keys,
        extensions: [
          new x509.SubjectAlternativeNameExtension([
            { type: 'url', value: `host://${t.slug}/${machineId}` },
          ]),
        ],
      });
      await client.hostCertificate.create({
        data: {
          hostId,
          serialNumber: normalizeSerialNumber(c.serialNumber),
          notBefore: c.notBefore,
          notAfter: c.notAfter,
        },
      });
      return Buffer.from(c.rawData);
    };
    const host = (extra: Record<string, unknown> = {}) =>
      client.host.create({
        data: {
          hostGroupId: group.id,
          machineId,
          hostname: 'LAPTOP',
          os: 'linux',
          keyType: 'SOFTWARE',
          keyFingerprint: randomBytes(32).toString('hex'),
          registeredFromIp: '10.0.0.7',
          status: 'APPROVED',
          ...extra,
        },
      });
    return { t, client, host, cert };
  }

  async function call(der: Buffer) {
    const request = {
      raw: {
        socket: { authorized: true, getPeerCertificate: () => ({ raw: der }) },
      },
    } as unknown as RequestWithHost;
    const context = {
      switchToHttp: () => ({ getRequest: () => request }),
    } as unknown as ExecutionContext;
    try {
      await guard.canActivate(context);
      return { status: 200, code: null, request };
    } catch (e) {
      const h = e as HttpException;
      return {
        status: h.getStatus(),
        code: (h.getResponse() as { code?: string }).code ?? null,
        request,
      };
    }
  }

  it('a revoked device is 423 device_revoked, never 401', async () => {
    const d = await device();
    const h = await d.host();
    const der = await d.cert(h.id);
    expect((await call(der)).status).toBe(200);
    await d.client.host.update({
      where: { id: h.id },
      data: { status: 'REVOKED' },
    });
    expect(await call(der)).toMatchObject({
      status: 423,
      code: 'device_revoked',
    });
  }, 60_000);

  it('a suspended workspace is 423 account_suspended; a deleting one 423 workspace_deleted', async () => {
    const d = await device();
    const der = await d.cert((await d.host()).id);
    await control.tenant.update({
      where: { id: d.t.id },
      data: { status: 'SUSPENDED' },
    });
    expect(await call(der)).toMatchObject({
      status: 423,
      code: 'account_suspended',
    });
    await control.tenant.update({
      where: { id: d.t.id },
      data: { status: 'DEPROVISIONING' },
    });
    expect(await call(der)).toMatchObject({
      status: 423,
      code: 'workspace_deleted',
    });
  }, 60_000);

  it('a removed device is 410 device_removed; so is any device of a personal account its owner deleted', async () => {
    const d = await device();
    const h = await d.host();
    const der = await d.cert(h.id);
    await d.client.host.update({
      where: { id: h.id },
      data: { status: 'REMOVED', removedAt: new Date() },
    });
    expect(await call(der)).toMatchObject({
      status: 410,
      code: 'device_removed',
    });

    // The workspace and its database are gone, its tombstone says why.
    const gone = await device();
    const der2 = await gone.cert((await gone.host()).id);
    await control.tenant.update({
      where: { id: gone.t.id },
      data: { slug: `${gone.t.slug}-x` },
    });
    expect(await call(der2)).toMatchObject({
      status: 423,
      code: 'workspace_deleted',
    });
    await control.deletedWorkspace.create({
      data: { slug: gone.t.slug, reason: 'account_deleted' },
    });
    expect(await call(der2)).toMatchObject({
      status: 410,
      code: 'device_removed',
    });
    await control.deletedWorkspace.delete({ where: { slug: gone.t.slug } });
  }, 60_000);

  it('a possible clone and the device it copies are told apart by their certificates', async () => {
    const d = await device('m-twin');
    const original = await d.host();
    const clone = await d.host({
      cloneOfHostId: original.id,
      status: 'PENDING',
    });
    const a = await call(await d.cert(original.id));
    const b = await call(await d.cert(clone.id));
    expect(a.request.hostContext).toMatchObject({
      hostId: original.id,
      status: 'APPROVED',
    });
    expect(b.request.hostContext).toMatchObject({
      hostId: clone.id,
      status: 'PENDING',
    });
  }, 60_000);

  it('standing vault grants: decided, sent to the device, withdrawn, and gone from its next config', async () => {
    const d = await device('m-vault');
    const h = await d.host({ ownerSubject: 'owner-1' });
    await d.client.secretVault.create({
      data: {
        hostId: h.id,
        kind: 'aws',
        ref: 'default',
        state: 'STORED',
        requestedBy: 'owner-1',
      },
    });
    const secrets = new SecretsService(
      { recordSafely: () => Promise.resolve() } as never,
      new SecretAlertBus(),
    );
    const ask = () =>
      secrets.createAccess(d.client, h.id, 'aws', 'default', {
        name: 'aws',
        path: '/usr/bin/aws',
        sha: 'a'.repeat(64),
      });
    const admin = {
      subject: 'admin-2',
      admin: true,
      company: true,
      freshSignIn: false,
    };
    const actor = { type: 'human' as const, id: 'u-admin' };
    const always = await ask();
    await secrets.decideAccess(
      d.client,
      d.t.id,
      actor,
      always.id,
      'ALLOW_ALWAYS',
      admin,
    );
    // A second, different program asks; allowed for 8 hours.
    const eight = await secrets.createAccess(d.client, h.id, 'aws', 'default', {
      name: 'terraform',
      path: '/usr/bin/terraform',
      sha: 'b'.repeat(64),
    });
    await secrets.decideAccess(
      d.client,
      d.t.id,
      actor,
      eight.id,
      'ALLOW_8H',
      admin,
    );
    const listed = await secrets.vaultGrants(d.client, h.id);
    expect(listed.map((g) => g.id).sort()).toEqual(
      [always.id, eight.id].sort(),
    );
    expect(listed.find((g) => g.id === always.id)!.until).toBeNull();
    expect((await secrets.listGrants(d.client)).length).toBe(2);

    await secrets.withdrawGrant(d.client, d.t.id, actor, always.id);
    expect(
      (await secrets.vaultGrants(d.client, h.id)).map((g) => g.id),
    ).toEqual([eight.id]);
    // An 8-hour grant that has ended is not sent either.
    await d.client.secretVaultAccess.update({
      where: { id: eight.id },
      data: { expiresAt: new Date(Date.now() - 1_000) },
    });
    expect(await secrets.vaultGrants(d.client, h.id)).toEqual([]);
  }, 60_000);
});
