import {
  PLATFORM_E2E_CLIENT_ID,
  PLATFORM_E2E_ROLE,
} from './support/platform-api-env';
import {
  EDGE_E2E_GATEWAY_KEY,
  EDGE_E2E_GATEWAY_TOKEN,
} from './support/edge-env';
import * as https from 'node:https';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { NativeConnection, Worker } from '@temporalio/worker';
import { WorkerAppModule } from '../src/temporal/worker-app.module';
import { ApprovalActivitiesFactory } from '../src/temporal/activities/approval.activities';
import type { AddressInfo } from 'node:net';
import { Client as PgClient } from 'pg';
import { vi } from 'vitest';
import { Test, TestingModule } from '@nestjs/testing';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import request from 'supertest';
import { generateAgentCsr } from '@manar/sdk-node';
import { AppModule } from '../src/app.module';
import { AgentMtlsAppModule } from '../src/agent-mtls/agent-mtls-app.module';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { KeycloakModule } from '../src/keycloak/keycloak.module';
import { TenantProvisioningService } from '../src/keycloak/tenant-provisioning.service';
import { AgentQuarantineService } from '../src/kill-switches/agent-quarantine.service';
import { EdgePeerService } from '../src/edge/edge-peer.service';
import { AUDIT_EVENT_TYPES } from '../src/audit/audit-event-types';
import { HOST_CLAUDE_CODE_TOOL } from '../src/tools/host-actions';
import {
  assignRealmRole,
  createPlatformClient,
  createRealmUser,
  deletePlatformClient,
  deleteRealm,
  getClientCredentialsToken,
  getUserToken,
} from './support/keycloak-test-helpers';
import { onCompanyPlan } from './support/free-entitlements';

/**
 * Manar edge (docs/edge.md) against the real stack: enrollment with a WireGuard key, address
 * allocation under concurrency, the peer state on every stop condition, the gateway sync API
 * (token, long poll, wake across two API instances, absent from the mTLS listener), the egress
 * allow-list (human admins only) and the host.claude-code actions.
 *
 * Engages the deployment-wide platform kill switch: run only against a stack of your own.
 */
interface EdgeBody {
  peerId: string;
  address: string;
  gatewayPublicKey: string;
  gatewayEndpoint: string;
  manarAddress: string;
  manarServerName: string;
  proxyAddress: string;
  keepaliveSeconds: number;
}
interface EnrolledAgent {
  agentId: string;
  slug: string;
  edge: EdgeBody;
  cert: { certificatePem: string; privateKeyPem: string };
}
interface Snapshot {
  version: number;
  full: boolean;
  peers: {
    id: string;
    publicKey: string;
    address: string;
    state: 'active' | 'cut';
    tenantSlug: string;
    agentSlug: string;
    allowHosts: string[];
  }[];
}
type Tenant = Awaited<ReturnType<TenantProvisioningService['provisionTenant']>>;

const PASSWORD = 'Passw0rd!Test';
const wgKey = () => randomBytes(32).toString('base64');
const short = (label: string) => `ed-${label}-${randomUUID().slice(0, 6)}`;

vi.setConfig({ testTimeout: 60_000 });

describe('Manar edge (e2e)', () => {
  let appA: NestFastifyApplication;
  let appB: NestFastifyApplication;
  let mtlsApp: NestFastifyApplication;
  let mtlsPort: number;
  let caChain: string;
  let control: ControlPrismaService;
  let tenants: TenantDatabaseManager;
  let provisioning: TenantProvisioningService;
  let platformClient: { uuid: string; secret: string };
  let platformToken: string;
  const created: Tenant[] = [];
  let t1: Tenant;
  let t2: Tenant;
  let admin1: string;
  let admin2: string;
  let readOnly1: string;
  let temporalConnection: NativeConnection;
  let temporalWorker: Worker;
  let temporalWorkerRun: Promise<void>;
  let workerFixture: TestingModule;

  const http = (app: NestFastifyApplication = appA) =>
    request(app.getHttpServer());
  const gateway = { Authorization: `Bearer ${EDGE_E2E_GATEWAY_TOKEN}` };

  async function userToken(t: Tenant, role: string): Promise<string> {
    const username = short(role.toLowerCase().replace('_', ''));
    const id = await createRealmUser(t.keycloakRealm!, {
      username,
      email: `${username}@example.test`,
      password: PASSWORD,
    });
    await assignRealmRole(t.keycloakRealm!, id, role);
    const secret = await control.secretReference.findFirstOrThrow({
      where: { tenantId: t.id, kind: 'KEYCLOAK_CLIENT_SECRET' },
    });
    return getUserToken({
      realm: t.keycloakRealm!,
      clientId: t.keycloakClientId!,
      clientSecret: secret.reference,
      username,
      password: PASSWORD,
    });
  }

  async function newAgent(
    token: string,
  ): Promise<{ id: string; slug: string; enrollToken: string }> {
    const slug = short('a');
    const id = (
      (
        await http()
          .post('/agents')
          .set('Authorization', `Bearer ${token}`)
          .send({ slug, displayName: slug })
          .expect(201)
      ).body as { id: string }
    ).id;
    const enrollToken = (
      (
        await http()
          .post(`/agents/${id}/enrollment-tokens`)
          .set('Authorization', `Bearer ${token}`)
          .expect(201)
      ).body as { token: string }
    ).token;
    return { id, slug, enrollToken };
  }

  async function enrollEdge(
    t: Tenant,
    agent: { id: string; slug: string; enrollToken: string },
    publicKey = wgKey(),
  ): Promise<EnrolledAgent> {
    const csr = await generateAgentCsr(`agent://${t.slug}/${agent.slug}`);
    const res = await http()
      .post('/agents/enroll')
      .send({
        token: agent.enrollToken,
        csr: csr.csrPem,
        edge: { wgPublicKey: publicKey },
      })
      .expect(201);
    const body = res.body as { certificate: string; edge: EdgeBody };
    return {
      agentId: agent.id,
      slug: agent.slug,
      edge: body.edge,
      cert: {
        certificatePem: body.certificate,
        privateKeyPem: csr.privateKeyPem,
      },
    };
  }

  async function snapshot(after = 0, app = appA): Promise<Snapshot> {
    return (
      await http(app)
        .get(`/internal/v1/edge/peers?after=${after}`)
        .set(gateway)
        .expect(200)
    ).body as Snapshot;
  }

  const row = (peerId: string) =>
    control.edgePeer.findUniqueOrThrow({ where: { id: peerId } });

  async function expectState(
    peerId: string,
    state: 'active' | 'cut',
    cutReason?: string,
  ): Promise<void> {
    const peer = (await snapshot()).peers.find((p) => p.id === peerId);
    expect(peer?.state).toBe(state);
    if (cutReason) expect((await row(peerId)).cutReason).toBe(cutReason);
  }

  function mtls(
    cert: EnrolledAgent['cert'],
    method: string,
    path: string,
    body?: unknown,
    headers: Record<string, string> = {},
  ): Promise<{ status: number; body: unknown }> {
    const text = body === undefined ? undefined : JSON.stringify(body);
    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          host: '127.0.0.1',
          port: mtlsPort,
          path,
          method,
          cert: cert.certificatePem,
          key: cert.privateKeyPem,
          ca: caChain,
          headers: {
            ...headers,
            ...(text
              ? {
                  'Content-Type': 'application/json',
                  'Content-Length': Buffer.byteLength(text),
                }
              : {}),
          },
        },
        (res) => {
          let data = '';
          res.on('data', (c: Buffer) => (data += c.toString()));
          res.on('end', () =>
            resolve({
              status: res.statusCode ?? 0,
              body: data ? (JSON.parse(data) as unknown) : undefined,
            }),
          );
        },
      );
      req.on('error', reject);
      if (text) req.write(text);
      req.end();
    });
  }

  async function bootHuman(): Promise<{
    app: NestFastifyApplication;
    fixture: TestingModule;
  }> {
    const fixture = await Test.createTestingModule({
      imports: [AppModule, KeycloakModule],
    }).compile();
    const app = fixture.createNestApplication<NestFastifyApplication>(
      new FastifyAdapter(),
    );
    await app.init();
    await app.getHttpAdapter().getInstance().ready();
    // Listening once up front: supertest would otherwise listen per request, which breaks under
    // the concurrent requests below.
    await app.listen(0, '127.0.0.1');
    return { app, fixture };
  }

  beforeAll(async () => {
    platformClient = await createPlatformClient(
      PLATFORM_E2E_CLIENT_ID,
      PLATFORM_E2E_ROLE,
    );
    platformToken = await getClientCredentialsToken(
      PLATFORM_E2E_CLIENT_ID,
      platformClient.secret,
    );

    const a = await bootHuman();
    appA = a.app;
    // A second API instance on the same databases: its own EdgePeerService, in-process queue and
    // LISTEN connection, as a second replica would have.
    appB = (await bootHuman()).app;

    caChain = readFileSync(
      process.env.AGENT_MTLS_CLIENT_CA_PATH ?? 'deploy/openbao/ca-chain.pem',
      'utf8',
    );
    const mtlsFixture = await Test.createTestingModule({
      imports: [AgentMtlsAppModule],
    }).compile();
    mtlsApp = mtlsFixture.createNestApplication<NestFastifyApplication>(
      new FastifyAdapter({
        https: {
          cert: readFileSync(
            process.env.AGENT_MTLS_SERVER_CERT_PATH ??
              'deploy/openbao/server-cert.pem',
          ),
          key: readFileSync(
            process.env.AGENT_MTLS_SERVER_KEY_PATH ??
              'deploy/openbao/server-key.pem',
          ),
          ca: caChain,
          requestCert: true,
          rejectUnauthorized: true,
        },
      }),
    );
    await mtlsApp.init();
    await mtlsApp.getHttpAdapter().getInstance().ready();
    await mtlsApp.listen(0, '127.0.0.1');
    mtlsPort = (mtlsApp.getHttpServer().address() as AddressInfo).port;

    // A real Temporal worker in-process, for the approval flow of host actions.
    workerFixture = await Test.createTestingModule({
      imports: [WorkerAppModule],
    }).compile();
    temporalConnection = await NativeConnection.connect({
      address: process.env.TEMPORAL_ADDRESS ?? 'localhost:7233',
    });
    temporalWorker = await Worker.create({
      connection: temporalConnection,
      namespace: process.env.TEMPORAL_NAMESPACE ?? 'default',
      taskQueue: process.env.TEMPORAL_TASK_QUEUE ?? 'manar-approvals',
      workflowsPath: join(
        process.cwd(),
        'src/temporal/workflows/approval.workflow.ts',
      ),
      activities: workerFixture.get(ApprovalActivitiesFactory).build(),
    });
    temporalWorkerRun = temporalWorker.run();

    control = appA.get(ControlPrismaService);
    tenants = appA.get(TenantDatabaseManager);
    provisioning = a.fixture.get(TenantProvisioningService);
    await control.platformKillSwitch.updateMany({
      where: { id: 'singleton' },
      data: { active: false },
    });

    t1 = await provisioning.provisionTenant({
      slug: short('t1'),
      name: 'Edge e2e one',
    });
    created.push(t1);
    t2 = await provisioning.provisionTenant({
      slug: short('t2'),
      name: 'Edge e2e two',
    });
    created.push(t2);
    await onCompanyPlan(control, t1.id);
    await onCompanyPlan(control, t2.id);
    admin1 = await userToken(t1, 'SECURITY_ADMIN');
    admin2 = await userToken(t2, 'SECURITY_ADMIN');
    readOnly1 = await userToken(t1, 'READ_ONLY');
  }, 240_000);

  afterAll(async () => {
    await control?.platformKillSwitch.updateMany({
      where: { id: 'singleton' },
      data: { active: false },
    });
    temporalWorker?.shutdown();
    await temporalWorkerRun;
    await temporalConnection?.close();
    await workerFixture?.close();
    await appA?.close();
    await appB?.close();
    await mtlsApp?.close();
    for (const t of created) {
      if (t.keycloakRealm)
        await deleteRealm(t.keycloakRealm).catch(() => undefined);
      const admin = new PgClient({
        connectionString: process.env.CONTROL_DATABASE_URL,
      });
      await admin.connect();
      if (t.databaseBinding?.databaseName)
        await admin.query(
          `DROP DATABASE IF EXISTS "${t.databaseBinding.databaseName}" WITH (FORCE)`,
        );
      await admin.query('DELETE FROM "edge_peers" WHERE "tenantId" = $1', [
        t.id,
      ]);
      await admin.query(
        'DELETE FROM "tenant_database_bindings" WHERE "tenantId" = $1',
        [t.id],
      );
      await admin.query(
        'DELETE FROM "secret_references" WHERE "tenantId" = $1',
        [t.id],
      );
      await admin.query('DELETE FROM "tenants" WHERE "id" = $1', [t.id]);
      await admin.end();
    }
    await deletePlatformClient(platformClient?.uuid, PLATFORM_E2E_ROLE);
  }, 120_000);

  describe('enrollment', () => {
    it('returns the edge object of the contract and an active peer', async () => {
      const agent = await enrollEdge(t1, await newAgent(admin1));
      expect(agent.edge).toEqual({
        peerId: expect.any(String) as string,
        address: expect.stringMatching(
          /^100\.88\.\d{1,3}\.\d{1,3}\/32$/,
        ) as string,
        gatewayPublicKey: EDGE_E2E_GATEWAY_KEY,
        gatewayEndpoint: 'edge.example.test:51820',
        manarAddress: '100.88.0.1:443',
        manarServerName: 'agents.example.test',
        proxyAddress: '100.88.0.1:3128',
        keepaliveSeconds: 25,
      });
      expect(agent.edge.address).not.toBe('100.88.0.1/32');
      const peer = (await snapshot()).peers.find(
        (p) => p.id === agent.edge.peerId,
      );
      expect(peer).toMatchObject({
        state: 'active',
        tenantSlug: t1.slug,
        agentSlug: agent.slug,
        allowHosts: [],
      });
    });

    it('re-enrolling replaces the key and keeps the peer id and address', async () => {
      const a = await newAgent(admin1);
      const first = await enrollEdge(t1, a);
      const enrollToken = (
        (
          await http()
            .post(`/agents/${a.id}/enrollment-tokens`)
            .set('Authorization', `Bearer ${admin1}`)
            .expect(201)
        ).body as { token: string }
      ).token;
      const newKey = wgKey();
      const second = await enrollEdge(t1, { ...a, enrollToken }, newKey);
      expect(second.edge.peerId).toBe(first.edge.peerId);
      expect(second.edge.address).toBe(first.edge.address);
      const peers = (await snapshot()).peers.filter(
        (p) => p.agentSlug === a.slug && p.tenantSlug === t1.slug,
      );
      expect(peers).toHaveLength(1);
      expect(peers[0]!.publicKey).toBe(newKey);
    });

    it("refuses another agent's key (409) and an invalid key (400)", async () => {
      const owner = await enrollEdge(t1, await newAgent(admin1));
      const key = (await row(owner.edge.peerId)).publicKey;
      const other = await newAgent(admin2);
      const csr = await generateAgentCsr(`agent://${t2.slug}/${other.slug}`);
      await http()
        .post('/agents/enroll')
        .send({
          token: other.enrollToken,
          csr: csr.csrPem,
          edge: { wgPublicKey: key },
        })
        .expect(409);
      // A guessed token reveals nothing about keys: the same uniform 401, never 409.
      const probe = await http()
        .post('/agents/enroll')
        .send({
          token: `${t2.slug}:${other.slug}:${'A'.repeat(43)}`,
          csr: csr.csrPem,
          edge: { wgPublicKey: key },
        })
        .expect(401);
      expect(probe.body).toMatchObject({ message: 'Invalid enrollment token' });
      // Refused before the token was spent: the same token enrolls with the agent's own key.
      await enrollEdge(t2, other);
      const third = await newAgent(admin1);
      await http()
        .post('/agents/enroll')
        .send({
          token: third.enrollToken,
          csr: 'x',
          edge: { wgPublicKey: 'short' },
        })
        .expect(400);
    });

    it('a bad token gets the same 401 and the same audit event with or without edge', async () => {
      const db = await tenants.getClient(t1.id);
      const failures = () =>
        db.auditEvent.findMany({
          where: { eventType: AUDIT_EVENT_TYPES.AGENT_ENROLLMENT_FAILED },
          orderBy: { sequence: 'asc' },
        });
      const before = (await failures()).length;
      const token = `${t1.slug}:${short('ghost')}:${'B'.repeat(43)}`;
      const plain = await http()
        .post('/agents/enroll')
        .send({ token, csr: 'x' })
        .expect(401);
      const withEdge = await http()
        .post('/agents/enroll')
        .send({ token, csr: 'x', edge: { wgPublicKey: wgKey() } })
        .expect(401);
      expect(withEdge.body).toEqual(plain.body);
      const added = (await failures()).slice(before);
      expect(added).toHaveLength(2);
      expect(added[1]!.actor).toEqual(added[0]!.actor);
      expect(added[1]!.data).toEqual(added[0]!.data);
      expect(added[0]!.data).toEqual({ reason: 'not_found' });
    });

    it('allocates distinct addresses to concurrent enrollments across tenants and API instances', async () => {
      const agents = await Promise.all([
        ...Array.from({ length: 6 }, () =>
          newAgent(admin1).then((a) => ({ t: t1, a })),
        ),
        ...Array.from({ length: 6 }, () =>
          newAgent(admin2).then((a) => ({ t: t2, a })),
        ),
      ]);
      const viaHttp = await Promise.all(
        agents.map(({ t, a }) => enrollEdge(t, a)),
      );
      // Straight at the service on both instances: the database lock, not one process's queue,
      // is what keeps addresses apart.
      const services = [appA.get(EdgePeerService), appB.get(EdgePeerService)];
      const direct = await Promise.all(
        Array.from({ length: 16 }, (_, i) =>
          services[i % 2]!.enroll({
            tenantId: i % 3 === 0 ? t2.id : t1.id,
            tenantSlug: i % 3 === 0 ? t2.slug : t1.slug,
            agentId: randomUUID(),
            agentSlug: `synthetic-${i}`,
            publicKey: wgKey(),
          }),
        ),
      );
      const addresses = [
        ...viaHttp.map((e) => e.edge.address),
        ...direct.map((e) => e.address),
      ];
      expect(new Set(addresses).size).toBe(addresses.length);
      const all = await control.edgePeer.findMany({
        select: { address: true },
      });
      expect(new Set(all.map((p) => p.address)).size).toBe(all.length);
      // A synthetic agent id exists in no tenant database: cut, never active.
      const synthetic = await control.edgePeer.findUniqueOrThrow({
        where: { id: direct[0]!.peerId },
      });
      expect(synthetic).toMatchObject({
        state: 'cut',
        cutReason: 'agent_not_found',
      });
    });
  });

  describe('gateway sync API', () => {
    let agent: EnrolledAgent;
    beforeAll(async () => {
      agent = await enrollEdge(t1, await newAgent(admin1));
    });

    it('needs the gateway token, compared exactly, and says nothing else', async () => {
      for (const auth of [
        undefined,
        'Bearer wrong',
        `Bearer ${EDGE_E2E_GATEWAY_TOKEN}x`,
        EDGE_E2E_GATEWAY_TOKEN,
      ]) {
        const req = http().get('/internal/v1/edge/peers?after=0');
        if (auth) void req.set('Authorization', auth);
        const res = await req.expect(401);
        expect(res.body).toEqual({ statusCode: 401, message: 'Unauthorized' });
      }
      await http()
        .post('/internal/v1/edge/events')
        .send({ events: [] })
        .expect(401);
      // Through an ingress (forwarding headers): absent, even with the right token.
      for (const header of ['X-Forwarded-For', 'Forwarded', 'X-Real-IP'])
        await http()
          .get('/internal/v1/edge/peers?after=0')
          .set(gateway)
          .set(
            header,
            header === 'Forwarded' ? 'for=203.0.113.9' : '203.0.113.9',
          )
          .expect(404);
      const full = await snapshot(0);
      expect(full.full).toBe(true);
      expect(full.peers.some((p) => p.id === agent.edge.peerId)).toBe(true);
      // A version from the future (a reset server) is answered with the full set too.
      expect((await snapshot(full.version + 1000)).full).toBe(true);
    });

    it('does not exist on the agent mTLS listener', async () => {
      const get = await mtls(
        agent.cert,
        'GET',
        '/internal/v1/edge/peers?after=0',
        undefined,
        gateway,
      );
      expect(get.status).toBe(404);
      const post = await mtls(
        agent.cert,
        'POST',
        '/internal/v1/edge/events',
        { events: [] },
        gateway,
      );
      expect(post.status).toBe(404);
      // The certificate itself works on that listener.
      expect((await mtls(agent.cert, 'GET', '/agent/v1/whoami')).status).toBe(
        200,
      );
    });

    it('returns deltas only, and holds a poll with nothing new', async () => {
      const { version } = await snapshot(0);
      const service = appA.get(EdgePeerService);
      const started = Date.now();
      const idle = await service.poll(version, 1_500);
      expect(Date.now() - started).toBeGreaterThanOrEqual(1_400);
      expect(idle).toEqual({ version, full: false, peers: [] });

      await http()
        .post(`/agents/${agent.agentId}/kill-switch`)
        .set('Authorization', `Bearer ${admin1}`)
        .send({})
        .expect(201);
      const delta = await snapshot(version);
      expect(delta.full).toBe(false);
      expect(delta.version).toBeGreaterThan(version);
      expect(delta.peers.map((p) => p.id)).toContain(agent.edge.peerId);
      expect(delta.peers.find((p) => p.id === agent.edge.peerId)?.state).toBe(
        'cut',
      );
      await http()
        .post(`/agents/${agent.agentId}/kill-switch/deactivate`)
        .set('Authorization', `Bearer ${admin1}`)
        .expect(201);
    });

    it('a change on one API instance wakes a long poll waiting on the other within 2 s', async () => {
      await snapshot(0, appA); // the first poll opens instance A's LISTEN connection
      await new Promise((r) => setTimeout(r, 500));
      // A lost LISTEN connection comes back by itself, without waiting for a poll.
      const serviceA = appA.get(EdgePeerService);
      expect(serviceA.listening).toBe(true);
      serviceA.dropListenerForTest();
      expect(serviceA.listening).toBe(false);
      await new Promise((r) => setTimeout(r, 1_500));
      expect(serviceA.listening).toBe(true);
      const { version } = await snapshot(0, appA);
      const started = Date.now();
      const waiting = http(appA)
        .get(`/internal/v1/edge/peers?after=${version}`)
        .set(gateway);
      const pending = waiting.then((res) => ({ res, at: Date.now() }));
      await new Promise((r) => setTimeout(r, 1_000));
      const changedAt = Date.now();
      await http(appB)
        .post(`/agents/${agent.agentId}/kill-switch`)
        .set('Authorization', `Bearer ${admin1}`)
        .send({})
        .expect(201);
      const { res, at } = await pending;
      expect(res.status).toBe(200);
      const body = res.body as Snapshot;
      expect(body.peers.find((p) => p.id === agent.edge.peerId)?.state).toBe(
        'cut',
      );
      expect(at - changedAt).toBeLessThan(2_000);
      expect(at - started).toBeLessThan(5_000);
      await http(appB)
        .post(`/agents/${agent.agentId}/kill-switch/deactivate`)
        .set('Authorization', `Bearer ${admin1}`)
        .expect(201);
    });

    it('writes egress events into the tenant of each peer, hostnames only', async () => {
      const other = await enrollEdge(t2, await newAgent(admin2));
      const at = new Date().toISOString();
      const event = (
        peerId: string,
        host: string,
        decision: 'allowed' | 'denied',
      ) => ({
        peerId,
        at,
        host,
        port: 443,
        decision,
        reason: decision === 'allowed' ? 'allowed' : 'sni_mismatch',
        bytesUp: 10,
        bytesDown: 20,
        durationMs: 5,
      });
      const res = await http()
        .post('/internal/v1/edge/events')
        .set(gateway)
        .send({
          events: [
            event(agent.edge.peerId, 'Graph.Microsoft.com', 'allowed'),
            {
              ...event(other.edge.peerId, 'evil.example.net', 'denied'),
              ech: true,
            },
            event(randomUUID(), 'x.example.com', 'denied'),
            { ...event(agent.edge.peerId, 'example.com/path', 'allowed') },
            {
              ...event(agent.edge.peerId, 'b.example.com', 'denied'),
              reason: 'Not-Allowed',
            },
            {
              ...event(agent.edge.peerId, 'b.example.com', 'denied'),
              ech: 'yes',
            },
          ],
        })
        .expect(200);
      expect(res.body).toEqual({ accepted: 2, skipped: 4, duplicates: 0 });

      const db1 = await tenants.getClient(t1.id);
      const db2 = await tenants.getClient(t2.id);
      const in1 = await db1.auditEvent.findMany({
        where: { eventType: { startsWith: 'agent.egress.' } },
      });
      const in2 = await db2.auditEvent.findMany({
        where: { eventType: { startsWith: 'agent.egress.' } },
      });
      expect(
        in1.map((e) => [e.eventType, (e.data as { host: string }).host]),
      ).toEqual([
        [AUDIT_EVENT_TYPES.AGENT_EGRESS_ALLOWED, 'graph.microsoft.com'],
      ]);
      expect(in1[0]!.actor).toEqual({ type: 'agent', id: agent.agentId });
      expect(in1[0]!.data).toMatchObject({
        reason: 'allowed',
        ech: null,
        port: 443,
      });
      expect(in2[0]!.data).toMatchObject({ reason: 'sni_mismatch', ech: true });
      expect(
        in2.map((e) => [e.eventType, (e.data as { host: string }).host]),
      ).toEqual([[AUDIT_EVENT_TYPES.AGENT_EGRESS_DENIED, 'evil.example.net']]);

      await http()
        .post('/internal/v1/edge/events')
        .set(gateway)
        .send({
          events: Array.from({ length: 501 }, () =>
            event(agent.edge.peerId, 'a.example.com', 'allowed'),
          ),
        })
        .expect(400);
    });

    it('records a retried batch once, and one tenant failing does not fail the others', async () => {
      const other = await enrollEdge(t2, await newAgent(admin2));
      const at = new Date().toISOString();
      const event = (peerId: string, host: string) => ({
        peerId,
        at,
        host,
        port: 443,
        decision: 'allowed',
        reason: 'allowed',
        bytesUp: 1,
        bytesDown: 1,
        durationMs: 1,
      });
      const count = async (tenantId: string, host: string) =>
        (await tenants.getClient(tenantId)).auditEvent.count({
          where: {
            eventType: AUDIT_EVENT_TYPES.AGENT_EGRESS_ALLOWED,
            data: { path: ['host'], equals: host },
          },
        });
      const batch = {
        batchId: randomUUID(),
        events: [
          event(agent.edge.peerId, 'once.example.com'),
          event(other.edge.peerId, 'once.example.com'),
        ],
      };
      const first = await http()
        .post('/internal/v1/edge/events')
        .set(gateway)
        .send(batch)
        .expect(200);
      expect(first.body).toEqual({ accepted: 2, skipped: 0, duplicates: 0 });
      const retry = await http()
        .post('/internal/v1/edge/events')
        .set(gateway)
        .send(batch)
        .expect(200);
      expect(retry.body).toEqual({ accepted: 0, skipped: 0, duplicates: 2 });
      expect(await count(t1.id, 'once.example.com')).toBe(1);
      expect(await count(t2.id, 'once.example.com')).toBe(1);
      // The gateway sends a UUID per batch; anything else is refused.
      await http()
        .post('/internal/v1/edge/events')
        .set(gateway)
        .send({ ...batch, batchId: 'b-1' })
        .expect(400);

      // Tenant two suspended (its database refused): tenant one's events still land.
      await http(appA)
        .post(`/platform/v1/tenants/${t2.id}/suspend`)
        .set('Authorization', `Bearer ${platformToken}`)
        .expect(200);
      try {
        const partial = await http()
          .post('/internal/v1/edge/events')
          .set(gateway)
          .send({
            events: [
              event(agent.edge.peerId, 'part.example.com'),
              event(other.edge.peerId, 'part.example.com'),
            ],
          })
          .expect(200);
        expect(partial.body).toEqual({
          accepted: 1,
          skipped: 1,
          duplicates: 0,
        });
      } finally {
        await http(appA)
          .post(`/platform/v1/tenants/${t2.id}/resume`)
          .set('Authorization', `Bearer ${platformToken}`)
          .expect(200);
      }
      expect(await count(t1.id, 'part.example.com')).toBe(1);
    });
  });

  describe('peer state: cut on every stop condition, active only when none holds', () => {
    let agent: EnrolledAgent;
    let bystander: EnrolledAgent;
    let otherTenant: EnrolledAgent;
    const as = (token: string) => ({ Authorization: `Bearer ${token}` });

    beforeAll(async () => {
      agent = await enrollEdge(t1, await newAgent(admin1));
      bystander = await enrollEdge(t1, await newAgent(admin1));
      otherTenant = await enrollEdge(t2, await newAgent(admin2));
    });

    it('agent kill switch and quarantine: each cuts, the peer returns only when both are cleared', async () => {
      const before = (await snapshot(0)).version;
      await http()
        .post(`/agents/${agent.agentId}/kill-switch`)
        .set(as(admin1))
        .send({})
        .expect(201);
      await expectState(agent.edge.peerId, 'cut', 'agent_kill_switch_active');
      expect((await row(agent.edge.peerId)).version).toBeGreaterThan(before);

      const db = await tenants.getClient(t1.id);
      await appA.get(AgentQuarantineService).quarantine(db, t1.id, {
        agentId: agent.agentId,
        reason: 'e2e',
        evidence: [],
        byAgentId: bystander.agentId,
        decisionId: randomUUID(),
        taskId: randomUUID(),
      });
      await http()
        .post(`/agents/${agent.agentId}/kill-switch/deactivate`)
        .set(as(admin1))
        .expect(201);
      await expectState(agent.edge.peerId, 'cut', 'agent_quarantined');
      await http()
        .post(`/agents/${agent.agentId}/quarantine/release`)
        .set(as(admin1))
        .send({})
        .expect(201);
      await expectState(agent.edge.peerId, 'active');
      await expectState(bystander.edge.peerId, 'active');
    });

    it('agent-group kill switch cuts its members only', async () => {
      const db = await tenants.getClient(t1.id);
      const group = await db.agentGroup.create({ data: { name: short('g') } });
      await db.agentGroupMembership.create({
        data: { agentId: agent.agentId, groupId: group.id },
      });
      await http()
        .post(`/agent-groups/${group.id}/kill-switch`)
        .set(as(admin1))
        .send({})
        .expect(201);
      await expectState(
        agent.edge.peerId,
        'cut',
        'agent_group_kill_switch_active',
      );
      await expectState(bystander.edge.peerId, 'active');
      await http()
        .post(`/agent-groups/${group.id}/kill-switch/deactivate`)
        .set(as(admin1))
        .expect(201);
      await expectState(agent.edge.peerId, 'active');
    });

    it('tenant kill switch cuts that tenant only', async () => {
      await http()
        .post('/tenants/kill-switch')
        .set(as(admin1))
        .send({})
        .expect(201);
      await expectState(agent.edge.peerId, 'cut', 'tenant_kill_switch_active');
      await expectState(bystander.edge.peerId, 'cut');
      await expectState(otherTenant.edge.peerId, 'active');
      await http()
        .post('/tenants/kill-switch/deactivate')
        .set(as(admin1))
        .expect(201);
      await expectState(agent.edge.peerId, 'active');
      await expectState(bystander.edge.peerId, 'active');
    });

    it('platform kill switch cuts every peer of every tenant; the platform release restores them', async () => {
      const engaged = (
        await http()
          .post('/kill-switches/platform')
          .set(as(admin1))
          .set(
            'X-Platform-Operator-Token',
            process.env.PLATFORM_KILL_SWITCH_OPERATOR_TOKEN ??
              'dev-only-platform-kill-switch-operator-token-change-me',
          )
          .send({ reason: 'edge e2e' })
          .expect(201)
      ).body as { activatedAt: string };
      const all = (await snapshot(0)).peers;
      expect(all.length).toBeGreaterThan(3);
      expect(all.every((p) => p.state === 'cut')).toBe(true);
      expect((await row(otherTenant.edge.peerId)).cutReason).toBe(
        'platform_kill_switch_active',
      );
      await http()
        .post('/platform/v1/kill-switch/release')
        .set('Authorization', `Bearer ${platformToken}`)
        .send({
          staff: 'edge-e2e',
          expectedEngagementId: new Date(engaged.activatedAt).toISOString(),
        })
        .expect(200);
      await expectState(agent.edge.peerId, 'active');
      await expectState(otherTenant.edge.peerId, 'active');
    });

    it('a suspended AI system cuts its agents; back to ACTIVE restores them', async () => {
      const db = await tenants.getClient(t1.id);
      const owner = await db.userProfile.findFirstOrThrow();
      const system = (
        await http()
          .post('/ai-systems')
          .set(as(admin1))
          .send({
            slug: short('ais'),
            name: 'Edge system',
            businessPurpose: 'e2e',
            ownerId: owner.id,
            businessUnit: 'e2e',
            environment: 'DEVELOPMENT',
            riskRationale: 'e2e',
          })
          .expect(201)
      ).body as { id: string };
      await http()
        .post(`/ai-systems/${system.id}/agents`)
        .set(as(admin1))
        .send({ agentId: agent.agentId })
        .expect(201);
      const reviewer = await userToken(t1, 'SECURITY_ADMIN');
      for (const [toState, token] of [
        ['REVIEW', admin1],
        ['ACTIVE', reviewer],
        ['SUSPENDED', admin1],
      ] as const)
        await http()
          .post(`/ai-systems/${system.id}/transitions`)
          .set(as(token))
          .send({ toState, reason: 'e2e' })
          .expect(201);
      await expectState(agent.edge.peerId, 'cut', 'ai_system_suspended');
      await http()
        .post(`/ai-systems/${system.id}/transitions`)
        .set(as(admin1))
        .send({ toState: 'ACTIVE', reason: 'e2e' })
        .expect(201);
      await expectState(agent.edge.peerId, 'active');
    });

    it('platform suspension of the tenant cuts its peers; resume restores them', async () => {
      await http(appA)
        .post(`/platform/v1/tenants/${t2.id}/suspend`)
        .set('Authorization', `Bearer ${platformToken}`)
        .expect(200);
      await expectState(otherTenant.edge.peerId, 'cut', 'tenant_suspended');
      await expectState(agent.edge.peerId, 'active');
      await http(appA)
        .post(`/platform/v1/tenants/${t2.id}/resume`)
        .set('Authorization', `Bearer ${platformToken}`)
        .expect(200);
      await expectState(otherTenant.edge.peerId, 'active');
    });

    it('revoking the agent (and its certificates) cuts it for good', async () => {
      await http()
        .post(`/agents/${bystander.agentId}/revoke`)
        .set(as(admin1))
        .send({ reason: 'e2e' })
        .expect(201);
      await expectState(bystander.edge.peerId, 'cut', 'agent_status_revoked');
    });

    it("a hanging tenant database cuts that tenant's peers and does not delay another tenant's cut beyond 3 s", async () => {
      const hung = await enrollEdge(t1, await newAgent(admin1));
      await expectState(hung.edge.peerId, 'active');
      await expectState(otherTenant.edge.peerId, 'active');
      // Hold a lock every peer read of tenant one needs, as a stuck database would.
      const base = new URL(process.env.TENANT_DB_BASE_URL!);
      base.pathname = `/${t1.databaseBinding!.databaseName}`;
      const locker = new PgClient({ connectionString: base.toString() });
      await locker.connect();
      await locker.query('BEGIN');
      await locker.query(
        'LOCK TABLE agent_egress_rules IN ACCESS EXCLUSIVE MODE',
      );
      try {
        const service = appA.get(EdgePeerService);
        const everything = service.allChanged(); // stuck on tenant one
        const started = Date.now();
        await http()
          .post(`/agents/${otherTenant.agentId}/kill-switch`)
          .set(as(admin2))
          .send({})
          .expect(201);
        await expectState(
          otherTenant.edge.peerId,
          'cut',
          'agent_kill_switch_active',
        );
        expect(Date.now() - started).toBeLessThan(3_000);
        await everything;
        // Fail closed: tenant one could not be read, so its peers are cut.
        await expectState(
          hung.edge.peerId,
          'cut',
          'enforcement_dependency_unavailable',
        );
      } finally {
        await locker.query('ROLLBACK');
        await locker.end();
      }
      // No other change: the recompute scheduled by the failed read restores it within seconds.
      const deadline = Date.now() + 15_000;
      while (
        (await row(hung.edge.peerId)).state !== 'active' &&
        Date.now() < deadline
      )
        await new Promise((r) => setTimeout(r, 500));
      await expectState(hung.edge.peerId, 'active');
      await http()
        .post(`/agents/${otherTenant.agentId}/kill-switch/deactivate`)
        .set(as(admin2))
        .expect(201);
      await expectState(otherTenant.edge.peerId, 'active');
    });

    it('an expired certificate cuts the peer, at the expiry, without any other change', async () => {
      const expiring = await enrollEdge(t1, await newAgent(admin1));
      const db = await tenants.getClient(t1.id);
      await db.agentCertificate.updateMany({
        where: { agentId: expiring.agentId },
        data: { notAfter: new Date(Date.now() + 2_000) },
      });
      await appA.get(EdgePeerService).agentChanged(t1.id, expiring.agentId);
      await expectState(expiring.edge.peerId, 'active');
      await new Promise((r) => setTimeout(r, 3_500));
      await expectState(expiring.edge.peerId, 'cut', 'certificate_expired');
    });
  });

  describe('egress allow-list', () => {
    let agent: EnrolledAgent;
    beforeAll(async () => {
      agent = await enrollEdge(t1, await newAgent(admin1));
    });
    const path = () => `/agents/${agent.agentId}/egress-rules`;

    it('only a human tenant admin can change it; never an agent certificate or a read-only user', async () => {
      await http().post(path()).send({ host: 'a.example.com' }).expect(401);
      await http()
        .post(path())
        .set('Authorization', `Bearer ${readOnly1}`)
        .send({ host: 'a.example.com' })
        .expect(403);
      await http()
        .get(path())
        .set('Authorization', `Bearer ${readOnly1}`)
        .expect(403);
      // Another tenant's admin cannot see this tenant's agent.
      await http()
        .post(path())
        .set('Authorization', `Bearer ${admin2}`)
        .send({ host: 'a.example.com' })
        .expect(404);
      const viaMtls = await mtls(agent.cert, 'POST', path(), {
        host: 'a.example.com',
      });
      expect(viaMtls.status).toBe(404);
      expect((await mtls(agent.cert, 'GET', path())).status).toBe(404);
      expect(
        await control.edgePeer.findUniqueOrThrow({
          where: { id: agent.edge.peerId },
        }),
      ).toMatchObject({ allowHosts: [] });
    });

    it('GET /agents/:id/edge: the peer state for a tenant admin, nothing for anyone else', async () => {
      const edgePath = `/agents/${agent.agentId}/edge`;
      const res = await http()
        .get(edgePath)
        .set('Authorization', `Bearer ${admin1}`)
        .expect(200);
      const peer = await row(agent.edge.peerId);
      expect(res.body).toEqual({
        enrolled: true,
        state: peer.state,
        ...(peer.state === 'cut' && {
          cutReasons: peer.cutReason ? [peer.cutReason] : [],
        }),
        address: peer.address,
        updatedAt: peer.updatedAt.toISOString(),
      });
      await http().get(edgePath).expect(401);
      await http()
        .get(edgePath)
        .set('Authorization', `Bearer ${readOnly1}`)
        .expect(403);
      await http()
        .get(edgePath)
        .set('Authorization', `Bearer ${admin2}`)
        .expect(404);
      expect((await mtls(agent.cert, 'GET', edgePath)).status).toBe(404);

      const plain = await newAgent(admin1);
      expect(
        (
          await http()
            .get(`/agents/${plain.id}/edge`)
            .set('Authorization', `Bearer ${admin1}`)
            .expect(200)
        ).body,
      ).toEqual({ enrolled: false });
    });

    it('validates hosts', async () => {
      for (const host of [
        '10.1.2.3',
        'example.com:443',
        'example.com/x',
        '*.com',
        'a.*.com',
        '*',
        '',
        '*.co.uk',
        '*.github.io',
        'db.internal',
        'printer.local',
        'api.svc',
        'nas.lan',
        'git.corp',
      ])
        await http()
          .post(path())
          .set('Authorization', `Bearer ${admin1}`)
          .send({ host })
          .expect(400);
    });

    it('adds and removes rules, audits each change and projects them into the peer with a version bump', async () => {
      const before = (await row(agent.edge.peerId)).version;
      const added = (
        await http()
          .post(path())
          .set('Authorization', `Bearer ${admin1}`)
          .send({ host: 'API.Example.com', reason: 'vendor API' })
          .expect(201)
      ).body as { id: string; host: string };
      expect(added.host).toBe('api.example.com');
      await http()
        .post(path())
        .set('Authorization', `Bearer ${admin1}`)
        .send({ host: '*.github.com' })
        .expect(201);
      await http()
        .post(path())
        .set('Authorization', `Bearer ${admin1}`)
        .send({ host: 'api.example.com' })
        .expect(409);

      const peer = await row(agent.edge.peerId);
      expect(peer.allowHosts).toEqual(['*.github.com', 'api.example.com']);
      expect(peer.version).toBeGreaterThan(before);
      expect(
        (await snapshot(before)).peers.find((p) => p.id === agent.edge.peerId)
          ?.allowHosts,
      ).toEqual(['*.github.com', 'api.example.com']);
      const listed = (
        await http()
          .get(path())
          .set('Authorization', `Bearer ${admin1}`)
          .expect(200)
      ).body as { items: { host: string }[] };
      expect(listed.items.map((r) => r.host)).toEqual([
        '*.github.com',
        'api.example.com',
      ]);

      await http()
        .delete(`${path()}/${added.id}`)
        .set('Authorization', `Bearer ${admin1}`)
        .expect(204);
      await http()
        .delete(`${path()}/${added.id}`)
        .set('Authorization', `Bearer ${admin1}`)
        .expect(404);
      expect((await row(agent.edge.peerId)).allowHosts).toEqual([
        '*.github.com',
      ]);

      const db = await tenants.getClient(t1.id);
      const events = await db.auditEvent.findMany({
        where: { eventType: { startsWith: 'agent.egress_rule.' } },
        orderBy: { sequence: 'asc' },
      });
      expect(events.map((e) => e.eventType)).toEqual([
        AUDIT_EVENT_TYPES.AGENT_EGRESS_RULE_ADDED,
        AUDIT_EVENT_TYPES.AGENT_EGRESS_RULE_ADDED,
        AUDIT_EVENT_TYPES.AGENT_EGRESS_RULE_REMOVED,
      ]);
      expect(
        events.every((e) => (e.actor as { type: string }).type === 'human'),
      ).toBe(true);
    });
  });

  describe('host.claude-code local actions', () => {
    it('are registered at edge enrollment and decided like any action: reads run, bash waits for approval', async () => {
      const agent = await enrollEdge(t2, await newAgent(admin2));
      const db = await tenants.getClient(t2.id);
      const tool = await db.tool.findUniqueOrThrow({
        where: { name: HOST_CLAUDE_CODE_TOOL },
        include: { actions: true },
      });
      expect(tool.enabled).toBe(false);
      expect(tool.actions.find((a) => a.name === 'bash')).toMatchObject({
        mutating: true,
        destructive: true,
      });

      const task = (
        await http()
          .post('/tasks')
          .set('Authorization', `Bearer ${admin2}`)
          .send({
            name: 'Claude Code session',
            assignedAgentId: agent.agentId,
            allowedToolActions: ['read', 'bash', 'edit'].map((actionId) => ({
              toolId: HOST_CLAUDE_CODE_TOOL,
              actionId,
            })),
            allowedResourceSelectors: [
              { toolId: HOST_CLAUDE_CODE_TOOL, pattern: '*' },
            ],
            forbiddenActions: [],
            expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
          })
          .expect(201)
      ).body as { id: string };
      const authorize = (actionId: string, resource: string) =>
        mtls(agent.cert, 'POST', '/agent/v1/authorize', {
          taskId: task.id,
          toolId: HOST_CLAUDE_CODE_TOOL,
          actionId,
          resource,
        });

      expect(
        (await authorize('read', '/home/dev/project/README.md')).body,
      ).toMatchObject({ decision: 'ALLOW' });
      // APPROVAL_REQUIRED opens an approval the hook can poll; a person approves; the poll says
      // APPROVED with the same agent identity (no grant redemption: Manar runs nothing).
      const pending = (await authorize('bash', 'rm -rf /tmp/x')).body as {
        decision: string;
        approvalId: string;
        expiresAt: string;
      };
      expect(pending).toMatchObject({
        decision: 'APPROVAL_REQUIRED',
        approvalId: expect.any(String) as string,
        expiresAt: expect.any(String) as string,
      });
      const poll = async () =>
        (
          await mtls(
            agent.cert,
            'GET',
            `/agent/v1/approvals/${pending.approvalId}`,
          )
        ).body as { status: string; actionId: string; resource: string };
      expect(await poll()).toMatchObject({
        status: 'PENDING',
        actionId: 'bash',
        resource: 'rm -rf /tmp/x',
      });
      await http()
        .post(`/approvals/${pending.approvalId}/decide`)
        .set('Authorization', `Bearer ${admin2}`)
        .send({ decision: 'APPROVE' })
        .expect(201);
      expect((await poll()).status).toBe('APPROVED');
      // Another agent cannot see it.
      const stranger = await enrollEdge(t2, await newAgent(admin2));
      expect(
        (
          await mtls(
            stranger.cert,
            'GET',
            `/agent/v1/approvals/${pending.approvalId}`,
          )
        ).status,
      ).toBe(404);
      expect((await authorize('write', '/etc/passwd')).body).toMatchObject({
        decision: 'DENY',
      });
      // Manar never executes a host action itself.
      const invoked = await mtls(agent.cert, 'POST', '/agent/v1/tools/invoke', {
        taskId: task.id,
        toolId: HOST_CLAUDE_CODE_TOOL,
        actionId: 'read',
        resource: '/x',
        params: {},
      });
      expect(invoked.status).toBeGreaterThanOrEqual(400);
    });
  });
});
