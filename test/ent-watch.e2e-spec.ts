import { Test } from '@nestjs/testing';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { createHash, randomBytes, randomUUID, webcrypto } from 'node:crypto';
import { Client as PgClient } from 'pg';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AppModule } from '../src/app.module';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { canonical } from '../src/enterprise/watch/device-signature';

/**
 * WATCH device API (src/enterprise/watch) against real Postgres: off unless the tenant's
 * `enterprise` flag is on, enrolment with a hashed key, every other route signed by the device key,
 * metadata-only events, tamper signals, and the long-poll.
 */
describe('Enterprise WATCH device API (e2e)', () => {
  let app: NestFastifyApplication;
  let control: ControlPrismaService;
  let manager: TenantDatabaseManager;
  let tenantId: string;
  let databaseName: string;
  const enrolKey = `wk_${randomBytes(24).toString('base64url')}`;
  const http = () => request(app.getHttpServer());

  const keyPair = () =>
    webcrypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify'],
    );

  const signedHeaders = async (
    pair: webcrypto.CryptoKeyPair,
    deviceId: string,
    method: string,
    path: string,
    body: string,
    time = Date.now(),
  ) => {
    const sig = await webcrypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      pair.privateKey,
      Buffer.from(canonical(method, path, time, body)),
    );
    return {
      'content-type': 'application/json',
      'x-watch-tenant': tenantId,
      'x-watch-device': deviceId,
      'x-watch-time': String(time),
      'x-watch-sig': Buffer.from(sig).toString('base64url'),
    };
  };

  const enrol = async (
    pair: webcrypto.CryptoKeyPair,
    key = enrolKey,
    email: string | null = 'salem@mds.example',
  ) =>
    http()
      .post('/watch/v1/enrol')
      .send({
        tenantId,
        enrolKey: key,
        publicKeyJwk: await webcrypto.subtle.exportKey('jwk', pair.publicKey),
        profileEmail: email,
        browser: 'edge',
        extensionVersion: '0.1.0',
      });

  const idOf = (r: { body: unknown }) =>
    (r.body as { deviceId: string }).deviceId;

  const post = async (
    pair: webcrypto.CryptoKeyPair,
    deviceId: string,
    path: string,
    payload: unknown,
  ) => {
    const body = JSON.stringify(payload);
    return http()
      .post(path)
      .set(await signedHeaders(pair, deviceId, 'POST', path, body))
      .send(body);
  };

  const setFlag = (on: boolean) =>
    control.tenantCatalog.upsert({
      where: { tenantId },
      create: {
        tenantId,
        features: { enterprise: on },
        packs: [],
        model: undefined,
        updatedBy: 'e2e',
      },
      update: { features: { enterprise: on } },
    });

  beforeAll(async () => {
    const mod = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
    app = mod.createNestApplication<NestFastifyApplication>(
      new FastifyAdapter(),
      { rawBody: true },
    );
    await app.init();
    await app.getHttpAdapter().getInstance().ready();
    control = app.get(ControlPrismaService);
    manager = app.get(TenantDatabaseManager);
    const t = await manager.provisionTenant({
      slug: `ent-${randomUUID().slice(0, 8)}`,
      name: 'Ministry of Digital Services (example)',
    });
    tenantId = t.id;
    databaseName = t.databaseBinding!.databaseName;
    const db = await manager.getClient(tenantId);
    await db.entSettings.create({
      data: {
        orgNameEn: 'Ministry of Digital Services',
        orgNameAr: 'وزارة الخدمات الرقمية',
        orgShort: 'MDS',
        workWeek: {},
      },
    });
    const huda = await db.entPerson.create({
      data: { email: 'huda@mds.example', displayName: 'Huda Saleh' },
    });
    await db.entPerson.create({
      data: {
        email: 'salem@mds.example',
        displayName: 'Salem Rashid',
        managerId: huda.id,
        preferredLanguage: 'ar-AE',
      },
    });
    await db.entEnrolKey.create({
      data: {
        keyHash: createHash('sha256').update(enrolKey).digest('hex'),
        expiresAt: new Date(Date.now() + 86_400_000),
        createdBy: 'e2e',
      },
    });
  });

  afterAll(async () => {
    await control.enterpriseProfile.deleteMany({ where: { tenantId } });
    await control.tenantCatalog.deleteMany({ where: { tenantId } });
    await app.close();
    const pg = new PgClient({
      connectionString: process.env.CONTROL_DATABASE_URL,
    });
    await pg.connect();
    await pg.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
    await pg.query(
      'DELETE FROM tenant_database_bindings WHERE "tenantId" = $1',
      [tenantId],
    );
    await pg.query('DELETE FROM secret_references WHERE "tenantId" = $1', [
      tenantId,
    ]);
    await pg.query('DELETE FROM tenants WHERE id = $1', [tenantId]);
    await pg.end();
  });

  it('does not exist for a tenant without the flag (default off), nor with the flag but no profile', async () => {
    const pair = await keyPair();
    expect((await enrol(pair)).status).toBe(404);
    await setFlag(true);
    expect((await enrol(pair)).status).toBe(404);
    await control.enterpriseProfile.create({
      data: {
        tenantId,
        sector: 'GOVERNMENT',
        publicSlug: `mds-${tenantId.slice(0, 6)}`,
      },
    });
  });

  it('refuses a wrong or revoked enrolment key and a private or foreign key', async () => {
    const pair = await keyPair();
    expect((await enrol(pair, 'wk_wrong_0123456789abcdef')).status).toBe(401);
    const exported = await webcrypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign'],
    );
    const priv = await webcrypto.subtle.exportKey('jwk', exported.privateKey);
    const r = await http().post('/watch/v1/enrol').send({
      tenantId,
      enrolKey,
      publicKeyJwk: priv,
      browser: 'chrome',
      extensionVersion: '0.1.0',
    });
    expect(r.status).toBe(400);
  });

  it('enrols once per key, links the claimed email unverified, and audits it', async () => {
    const pair = await keyPair();
    const a = await enrol(pair);
    expect(a.status).toBe(201);
    const b = await enrol(pair);
    expect(idOf(b)).toBe(idOf(a));
    const db = await manager.getClient(tenantId);
    const d = await db.entDevice.findUniqueOrThrow({
      where: { id: idOf(a) },
    });
    expect(d.identityVerified).toBe(false);
    expect(d.personId).not.toBeNull();
    expect(
      await db.auditEvent.count({
        where: { eventType: 'ent.device.enrolled' },
      }),
    ).toBeGreaterThan(0);
  });

  it('signed routes refuse a bad signature, another path, a stale time, an unknown device', async () => {
    const pair = await keyPair();
    const deviceId = idOf(await enrol(pair));
    const body = JSON.stringify({ events: [] });
    const good = await signedHeaders(
      pair,
      deviceId,
      'POST',
      '/watch/v1/events',
      body,
    );
    const other = await keyPair();
    const forged = await signedHeaders(
      other,
      deviceId,
      'POST',
      '/watch/v1/events',
      body,
    );
    expect(
      (await http().post('/watch/v1/events').set(forged).send(body)).status,
    ).toBe(401);
    const wrongPath = await signedHeaders(
      pair,
      deviceId,
      'POST',
      '/watch/v1/heartbeat',
      body,
    );
    expect(
      (await http().post('/watch/v1/events').set(wrongPath).send(body)).status,
    ).toBe(401);
    const stale = await signedHeaders(
      pair,
      deviceId,
      'POST',
      '/watch/v1/events',
      body,
      Date.now() - 121_000,
    );
    expect(
      (await http().post('/watch/v1/events').set(stale).send(body)).status,
    ).toBe(401);
    expect(
      (
        await http()
          .post('/watch/v1/events')
          .set({ ...good, 'x-watch-device': randomUUID() })
          .send(body)
      ).status,
    ).toBe(401);
    // A changed body under a valid signature.
    expect(
      (
        await http()
          .post('/watch/v1/events')
          .set(good)
          .send(JSON.stringify({ events: [1] }))
      ).status,
    ).toBe(401);
  });

  it('events: metadata only, deduplicated by client id; a text field is refused', async () => {
    const pair = await keyPair();
    const deviceId = idOf(await enrol(pair));
    const ev = {
      clientEventId: randomUUID(),
      host: 'chatgpt.com',
      kind: 'send',
      outcome: 'block',
      ruleId: 'r-ids',
      trace: [{ ruleId: 'r-ids', result: 'block' }],
      counts: { national_id: 3 },
      packVersion: '2026.11.1',
      at: new Date().toISOString(),
    };
    expect(
      (await post(pair, deviceId, '/watch/v1/events', { events: [ev] })).status,
    ).toBe(204);
    expect(
      (await post(pair, deviceId, '/watch/v1/events', { events: [ev] })).status,
    ).toBe(204);
    const db = await manager.getClient(tenantId);
    expect(
      await db.entEvent.count({ where: { clientEventId: ev.clientEventId } }),
    ).toBe(1);
    const leaky = await post(pair, deviceId, '/watch/v1/events', {
      events: [
        { ...ev, clientEventId: randomUUID(), prompt: '784-1971-3958204-9' },
      ],
    });
    expect(leaky.status).toBe(400);
    expect(JSON.stringify(leaky.body)).not.toContain('784');
  });

  it('heartbeat: unpacked copy and a changed configuration open tamper signals once', async () => {
    const pair = await keyPair();
    const deviceId = idOf(await enrol(pair));
    const hb = (configHash: string, unpacked = false) =>
      post(pair, deviceId, '/watch/v1/heartbeat', {
        extensionVersion: '0.1.0',
        policyVersion: null,
        configHash,
        hints: { unpacked },
        visits: { '2026-11-04': { 'chatgpt.com': 2 } },
      });
    expect((await hb('a'.repeat(64))).status).toBe(204);
    expect((await hb('b'.repeat(64), true)).status).toBe(204);
    expect((await hb('b'.repeat(64), true)).status).toBe(204);
    const db = await manager.getClient(tenantId);
    const open = await db.entTamperSignal.findMany({
      where: { deviceId, closedAt: null },
    });
    expect(open.map((s) => s.kind).sort()).toEqual([
      'config_changed',
      'unpacked',
    ]);
    expect(
      (await db.entSiteVisit.findFirstOrThrow({ where: { deviceId } })).count,
    ).toBe(6);
  });

  it('policy: branding, the person language and manager; 204 when unchanged; long-poll holds', async () => {
    const pair = await keyPair();
    const deviceId = idOf(await enrol(pair));
    const get = async (q: string) =>
      http()
        .get(`/watch/v1/policy${q}`)
        .set(
          await signedHeaders(pair, deviceId, 'GET', '/watch/v1/policy', ''),
        );
    const p = await get('');
    expect(p.status).toBe(200);
    expect(p.body).toMatchObject({
      tenantId,
      language: 'ar',
      org: {
        nameEn: 'Ministry of Digital Services',
        nameAr: 'وزارة الخدمات الرقمية',
        short: 'MDS',
      },
      approver: { name: 'Huda Saleh', relation: 'manager' },
      unreadableFile: 'ASK',
    });
    expect((p.body as { org: { seeUrl: string } }).org.seeUrl).toMatch(
      /\/ar\/see\/mds-/,
    );
    const version = (p.body as { version: string }).version;
    expect((await get(`?since=${version}`)).status).toBe(204);
    const t0 = Date.now();
    expect((await get(`?since=${version}&wait=3`)).status).toBe(204);
    expect(Date.now() - t0).toBeGreaterThanOrEqual(2000);
  });

  it('identity proof is off until an issuer is configured (devices stay unverified)', async () => {
    const pair = await keyPair();
    const deviceId = idOf(await enrol(pair));
    const r = await post(pair, deviceId, '/watch/v1/identity/nonce', {
      redirectUri: `https://${'a'.repeat(32)}.chromiumapp.org/`,
    });
    expect(r.status).toBe(404);
  });

  it('turning the flag off removes the surface at once', async () => {
    const pair = await keyPair();
    const deviceId = idOf(await enrol(pair));
    await setFlag(false);
    expect(
      (await post(pair, deviceId, '/watch/v1/events', { events: [] })).status,
    ).toBe(404);
    await setFlag(true);
  });
});
