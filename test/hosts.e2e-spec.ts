import 'dotenv/config';
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
import { fakeConfigService } from './support/audit-test-config';

/** Hosts (docs/hosts.md) against a real tenant database. */
describe('Hosts (e2e)', () => {
  let control: ControlPrismaService;
  let manager: TenantDatabaseManager;
  let kafka: KafkaPublisherService;
  let audit: AuditService;
  let keys: InstallKeysService;
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
});
