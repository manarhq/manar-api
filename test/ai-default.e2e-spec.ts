import {
  PLATFORM_E2E_CLIENT_ID,
  PLATFORM_E2E_ROLE,
  PLATFORM_E2E_SUFFIX,
} from './support/platform-api-env';
import { Client as PgClient } from 'pg';
import { Test } from '@nestjs/testing';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import request from 'supertest';
import { ConfigService } from '@nestjs/config';
import { vi } from 'vitest';
import { AppModule } from '../src/app.module';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { AuditService } from '../src/audit/audit.service';
import { AiDefaultService } from '../src/tenant-settings/ai-default.service';
import {
  createPlatformClient,
  deletePlatformClient,
  deleteRealm,
  getClientCredentialsToken,
} from './support/keycloak-test-helpers';

const INTENT = 'tenant.settings.ai_default_intent';
const APPLIED = 'tenant.settings.ai_default_applied';

describe('ai:default-on audit trail against real Postgres (e2e)', () => {
  const suffix = PLATFORM_E2E_SUFFIX;
  let app: NestFastifyApplication;
  let control: ControlPrismaService;
  let tdm: TenantDatabaseManager;
  let realAudit: AuditService;
  let pc: { uuid: string; secret: string };
  let token: string;
  const made: { id: string; slug: string }[] = [];
  const http = () => request(app.getHttpServer());

  /** AuditService wrapper whose `record` can be told to fail for one event type, once. */
  let failOnce: string | null = null;
  const audit = {
    record: (c: unknown, t: string, input: { eventType: string }) => {
      if (failOnce && input.eventType === failOnce) {
        failOnce = null;
        return Promise.reject(new Error('injected audit failure'));
      }
      return realAudit.record(c as never, t, input as never);
    },
  };
  const service = () =>
    new AiDefaultService(
      control,
      tdm,
      audit as never,
      {
        get: (k: string, o?: object): unknown =>
          k === 'MANAR_DEPLOYMENT'
            ? 'hosted'
            : app.get(ConfigService).get(k, o as never),
      } as never,
    );

  async function provision(label: string, sector?: string) {
    const slug = `rv-${label}-${suffix}`;
    const res = await http()
      .post('/platform/v1/tenants')
      .set('Authorization', `Bearer ${token}`)
      .send({ slug, name: `rv ${label}`, ...(sector ? { sector } : {}) })
      .expect(201);
    const id = (res.body as { id: string }).id;
    made.push({ id, slug });
    return id;
  }
  const row = (id: string) =>
    control.tenant.findUniqueOrThrow({ where: { id } });
  const events = async (id: string, type: string) =>
    (await tdm.getClient(id)).auditEvent.findMany({
      where: { eventType: type },
      select: { data: true },
      orderBy: { timestamp: 'asc' },
    });
  /** Legacy shape: commercial-or-gov, old default false, no recorded choice. */
  const legacy = (id: string, data: object = {}) =>
    control.tenant.update({
      where: { id },
      data: {
        allowExternalAi: false,
        allowExternalAiChosen: false,
        aiDefaultNoticePending: false,
        aiOptInNoticePending: false,
        ...data,
      },
    });

  beforeAll(async () => {
    pc = await createPlatformClient(PLATFORM_E2E_CLIENT_ID, PLATFORM_E2E_ROLE);
    token = await getClientCredentialsToken(PLATFORM_E2E_CLIENT_ID, pc.secret);
    const m = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
    app = m.createNestApplication<NestFastifyApplication>(new FastifyAdapter());
    await app.init();
    await app.getHttpAdapter().getInstance().ready();
    control = app.get(ControlPrismaService);
    tdm = app.get(TenantDatabaseManager);
    realAudit = app.get(AuditService);
  }, 120_000);

  afterAll(async () => {
    await app?.close();
    await deletePlatformClient(pc?.uuid, PLATFORM_E2E_ROLE);
    const admin = new PgClient({
      connectionString: process.env.CONTROL_DATABASE_URL,
    });
    await admin.connect();
    for (const t of made) {
      await deleteRealm(t.slug).catch(() => undefined);
      const b = await admin.query(
        'SELECT "databaseName" FROM tenant_database_bindings WHERE "tenantId"=$1',
        [t.id],
      );
      for (const r of b.rows as { databaseName: string }[])
        await admin.query(
          `DROP DATABASE IF EXISTS "${r.databaseName}" WITH (FORCE)`,
        );
      await admin.query('DELETE FROM enterprise_profiles WHERE "tenantId"=$1', [
        t.id,
      ]);
      await admin.query(
        'DELETE FROM tenant_database_bindings WHERE "tenantId"=$1',
        [t.id],
      );
      await admin.query('DELETE FROM secret_references WHERE "tenantId"=$1', [
        t.id,
      ]);
      await admin.query('DELETE FROM tenants WHERE id=$1', [t.id]);
    }
    await admin.end();
  }, 120_000);

  it('an intent whose flip never happened is never later reported as applied', async () => {
    const id = await provision('r6', 'COMMERCIAL');
    await legacy(id, { sector: 'COMMERCIAL' });
    const s1 = service();
    vi.spyOn(s1, 'guardedFlip').mockRejectedValueOnce(
      new Error('injected flip failure'),
    );
    const r1 = await s1.run({
      dryRun: false,
      includeEnterprise: true,
      onlyTenantIds: [id],
    });
    expect(r1.failed).toBeGreaterThanOrEqual(1);
    expect((await row(id)).allowExternalAi).toBe(false);
    const orphan = (await events(id, INTENT)).at(-1)!.data as {
      intentId: string;
    };
    await service().run({
      dryRun: false,
      includeEnterprise: true,
      onlyTenantIds: [id],
    }); // real flip, with completion
    expect((await row(id)).allowExternalAi).toBe(true);
    await service().run({
      dryRun: false,
      includeEnterprise: true,
      onlyTenantIds: [id],
    }); // reconcile pass
    const forOrphan = (await events(id, APPLIED)).filter(
      (e) => (e.data as { intentId?: string }).intentId === orphan.intentId,
    );
    // Run 1's intent was never applied: it may have no completion or one saying applied:false,
    // never a second switch-on next to run 2's.
    expect(
      forOrphan.every(
        (e) => (e.data as { applied: boolean }).applied === false,
      ),
    ).toBe(true);
  }, 180_000);
});
