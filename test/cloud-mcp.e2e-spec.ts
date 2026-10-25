import 'dotenv/config';
import { vi } from 'vitest';

// The endpoint is off by default; ConfigModule reads the environment at import time.
vi.hoisted(() => {
  process.env.MANAR_MCP_ENABLED = 'true';
  process.env.MANAR_MCP_HOST = 'mcp.manar.test';
});
import { randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { Client as PgClient } from 'pg';
import { Test } from '@nestjs/testing';
import type { ConfigService } from '@nestjs/config';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import type { FastifyInstance } from 'fastify';
import request from 'supertest';
import { decodeJwt } from 'jose';
import { AppModule } from '../src/app.module';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { KeycloakModule } from '../src/keycloak/keycloak.module';
import { KeycloakAdminClient } from '../src/keycloak/keycloak-admin.client';
import { TenantProvisioningService } from '../src/keycloak/tenant-provisioning.service';
import { OpenBaoKvClient } from '../src/openbao/openbao-kv.client';
import { AiAdvisoryClient } from '../src/ai-advisory/ai-advisory-client.service';
import type { AppConfig } from '../src/config/env.validation';
import {
  ensureMicrosoftFixtureTools,
  MICROSOFT_FIXTURE_APP,
  MICROSOFT_FIXTURE_IDS,
  MICROSOFT_GRAPH_TOOL,
} from '../src/cli/commands/microsoft-fixture-seed';
import { buildMicrosoftFixtureApp } from '../packages/demo-soc-tools/src/microsoft/fixture';
import { FIXTURE_SECOND_USER_ID } from '../packages/demo-soc-tools/src/microsoft/seed-data';
import {
  adminFetch,
  assignRealmRole,
  createRealmUser,
  deleteRealm,
  getUserToken,
} from './support/keycloak-test-helpers';
import { FakeAnalysisServiceServer } from './support/fake-analysis-service-server';
import {
  authorizationCode,
  describePage,
  exchangeCode,
} from './support/oidc-browser';
import type { Login } from './support/oidc-browser';

/**
 * docs/cloud-agents.md end to end against a real Keycloak. Every agent token
 * comes from the authorization code flow with PKCE, as Copilot Studio and
 * ChatGPT get them (test/support/oidc-browser.ts); the password grant is shown
 * not to produce a usable token. Covers discovery, the OAuth gate, the
 * governed tools/call path (ALLOW, DENY, quarantine), the agent role, the
 * recorded ChatGPT client, disconnecting, resuming a failed connection, and
 * Entra brokering that cannot take over an existing account.
 *
 * Keycloak must answer on the same address inside its container and from
 * the tests (start-dev --http-port=<published port>) for the brokering test:
 * the realm calls the upstream provider's token endpoint itself.
 */
describe('Cloud agents: public MCP with OAuth (e2e)', () => {
  const HOST = 'mcp.manar.test';
  const KC = process.env.KEYCLOAK_BASE_URL ?? 'http://localhost:8081';
  const PASSWORD = 'Passw0rd!Test';
  const COPILOT_CALLBACK = 'https://copilot.test/callback';
  const CHATGPT_CALLBACK =
    'https://chatgpt.com/connector_platform_oauth_redirect';
  const { userId } = MICROSOFT_FIXTURE_IDS;
  const shortSlug = (label: string) =>
    `cm-${label}-${randomUUID().slice(0, 8)}`;

  let app: NestFastifyApplication;
  let control: ControlPrismaService;
  let tenants: TenantDatabaseManager;
  let fixture: FastifyInstance;
  let fakeAnalysis: FakeAnalysisServiceServer;
  type Tenant = Awaited<
    ReturnType<TenantProvisioningService['provisionTenant']>
  >;
  let tenantA: Tenant;
  let tenantB: Tenant;
  let realm: string;
  let issuer: string;
  let ownerToken: string;
  let owner: { id: string; username: string; email: string };
  const extraRealms: string[] = [];

  const http = () => request(app.getHttpServer());
  const admin = () => `Bearer ${ownerToken}`;

  async function cleanupTenant(t: Tenant): Promise<void> {
    if (t.keycloakRealm) await deleteRealm(t.keycloakRealm);
    if (t.databaseBinding?.databaseName) {
      const pg = new PgClient({
        connectionString: process.env.CONTROL_DATABASE_URL,
      });
      await pg.connect();
      await pg.query(
        `DROP DATABASE IF EXISTS "${t.databaseBinding.databaseName}" WITH (FORCE)`,
      );
      await pg.end();
    }
    await control.tenantDatabaseBinding.deleteMany({
      where: { tenantId: t.id },
    });
    await control.secretReference.deleteMany({ where: { tenantId: t.id } });
    await control.tenant.deleteMany({ where: { id: t.id } });
  }

  async function consoleSecret(t: Tenant) {
    return (
      await control.secretReference.findFirstOrThrow({
        where: { tenantId: t.id, kind: 'KEYCLOAK_CLIENT_SECRET' },
      })
    ).reference;
  }

  async function kcJson<T>(path: string): Promise<T> {
    return (await (await adminFetch(path)).json()) as T;
  }

  async function person(role?: string): Promise<Login & { id: string }> {
    const username = shortSlug('p');
    const id = await createRealmUser(realm, {
      username,
      email: `${username}@example.test`,
      password: PASSWORD,
    });
    if (role) await assignRealmRole(realm, id, role);
    return { id, username, password: PASSWORD };
  }

  /** Authorization code flow + exchange: the token a vendor would hold. */
  async function vendorToken(
    client: { clientId: string; clientSecret: string; redirectUri: string },
    login: Login,
    scope = 'openid',
  ): Promise<string> {
    const flow = await authorizationCode({
      issuer,
      clientId: client.clientId,
      redirectUri: client.redirectUri,
      scope,
      logins: [login],
    });
    if (!('code' in flow)) {
      throw new Error(
        `No code (HTTP ${flow.status}): ${describePage(flow.page)}`,
      );
    }
    return exchangeCode({ issuer, ...client, ...flow });
  }

  let rpcId = 0;
  function mcp(
    path: string,
    token: string | undefined,
    method: string,
    params?: unknown,
  ) {
    rpcId += 1;
    const req = http()
      .post(path)
      .set('Accept', 'application/json, text/event-stream')
      .send({
        jsonrpc: '2.0',
        id: rpcId,
        method,
        ...(params ? { params } : {}),
      });
    return token ? req.set('Authorization', `Bearer ${token}`) : req;
  }

  async function auditCount(reason: string) {
    const tenantClient = await tenants.getClient(tenantA.id);
    const events = await tenantClient.auditEvent.findMany({
      where: { eventType: 'cloud_mcp.token_rejected' },
    });
    return events.filter(
      (e) => (e.data as { reason?: string }).reason === reason,
    ).length;
  }

  beforeAll(async () => {
    fakeAnalysis = new FakeAnalysisServiceServer();
    const analysisTarget = await fakeAnalysis.start();
    fixture = buildMicrosoftFixtureApp();
    await fixture.listen({ port: 0, host: '127.0.0.1' });
    const fixtureBase = `http://127.0.0.1:${(fixture.server.address() as AddressInfo).port}`;

    const moduleFixture = await Test.createTestingModule({
      imports: [AppModule, KeycloakModule],
    })
      .overrideProvider(AiAdvisoryClient)
      .useFactory({
        factory: (controlPrisma: ControlPrismaService) => {
          const values: Record<string, unknown> = {
            AI_ADVISORY_GRPC_TARGET: analysisTarget,
            AI_ADVISORY_TIMEOUT_MS: 2000,
            AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD: 3,
            AI_ADVISORY_CIRCUIT_BREAKER_COOLDOWN_MS: 30_000,
            AI_ADVISORY_LONGFORM_TIMEOUT_MS: 30_000,
            AI_ADVISORY_LONGFORM_CIRCUIT_BREAKER_THRESHOLD: 3,
            AI_ADVISORY_LONGFORM_CIRCUIT_BREAKER_COOLDOWN_MS: 30_000,
          };
          return new AiAdvisoryClient(
            { get: (k: string) => values[k] } as unknown as ConfigService<
              AppConfig,
              true
            >,
            controlPrisma,
          );
        },
        inject: [ControlPrismaService],
      })
      .compile();
    app = moduleFixture.createNestApplication<NestFastifyApplication>(
      new FastifyAdapter(),
    );
    await app.init();
    await app.getHttpAdapter().getInstance().ready();
    control = app.get(ControlPrismaService);
    tenants = app.get(TenantDatabaseManager);

    const provisioning = moduleFixture.get(TenantProvisioningService);
    tenantA = await provisioning.provisionTenant({
      slug: shortSlug('a'),
      name: 'Cloud MCP e2e A',
    });
    tenantB = await provisioning.provisionTenant({
      slug: shortSlug('b'),
      name: 'Cloud MCP e2e B',
    });
    realm = tenantA.keycloakRealm!;
    issuer = tenantA.keycloakIssuerUrl!;

    const username = shortSlug('owner');
    owner = {
      username,
      email: `${username}@example.test`,
      id: await createRealmUser(realm, {
        username,
        email: `${username}@example.test`,
        password: PASSWORD,
      }),
    };
    await assignRealmRole(realm, owner.id, 'TENANT_OWNER');
    ownerToken = await getUserToken({
      realm,
      clientId: tenantA.keycloakClientId!,
      clientSecret: await consoleSecret(tenantA),
      username,
      password: PASSWORD,
    });

    const kvPath = `tools/${shortSlug('ms')}`;
    await app
      .get(OpenBaoKvClient)
      .writeSecret(kvPath, { value: MICROSOFT_FIXTURE_APP.clientSecret });
    await ensureMicrosoftFixtureTools(await tenants.getClient(tenantA.id), {
      fixtureBaseUrl: fixtureBase,
      kvPath,
    });
  }, 180_000);

  afterAll(async () => {
    await app?.close();
    await fixture?.close();
    await fakeAnalysis?.stop();
    if (tenantA) await cleanupTenant(tenantA);
    if (tenantB) await cleanupTenant(tenantB);
    for (const r of extraRealms) await deleteRealm(r);
  }, 60_000);

  const standingTask = () => ({
    name: 'cloud agent standing task',
    allowedToolActions: [
      { toolId: MICROSOFT_GRAPH_TOOL, actionId: 'entra.user.get' },
    ],
    allowedResourceSelectors: [
      { toolId: MICROSOFT_GRAPH_TOOL, pattern: userId },
    ],
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    riskCeiling: 50,
  });

  interface Connected {
    agent: { id: string; slug: string };
    taskId: string;
    mcpUrl: string;
    resourceMetadataUrl: string;
    authorizationServer: string;
    tokenUrl: string;
    scopes: string[];
    role: string;
    clientId?: string;
    clientSecret?: string;
    registrationUrl?: string;
  }

  async function connect(
    platform: 'COPILOT_STUDIO' | 'CHATGPT',
    extra: Record<string, unknown> = {},
  ): Promise<Connected> {
    const res = await http()
      .post('/cloud-agents')
      .set('Authorization', admin())
      .send({
        slug: shortSlug(platform === 'CHATGPT' ? 'gpt' : 'cs'),
        displayName: `Cloud ${platform}`,
        platform,
        ...(platform === 'COPILOT_STUDIO'
          ? { redirectUris: [COPILOT_CALLBACK] }
          : {}),
        task: standingTask(),
        ...extra,
      });
    expect([res.status, res.body]).toEqual([201, expect.anything()]);
    return res.body as Connected;
  }

  const copilotClient = (agent: Connected) => ({
    clientId: agent.clientId!,
    clientSecret: agent.clientSecret!,
    redirectUri: COPILOT_CALLBACK,
  });

  describe('Copilot Studio (pre-registered client)', () => {
    let agent: Connected;
    let path: string;
    let token: string;
    let user: Login & { id: string };

    beforeAll(async () => {
      agent = await connect('COPILOT_STUDIO');
      path = new URL(agent.mcpUrl).pathname;
      user = await person(agent.role);
      token = await vendorToken(copilotClient(agent), user);
    }, 60_000);

    it('returns what the admin pastes into Copilot Studio; the token names the MCP URL and the agent role', () => {
      expect(agent.mcpUrl).toBe(
        `https://${HOST}/mcp/${tenantA.slug}/${agent.agent.slug}`,
      );
      expect(agent.authorizationServer).toBe(issuer);
      expect(agent.clientId).toBe(`manar-cloud-${agent.agent.slug}`);
      expect(agent.role).toBe(`manar-agent-${agent.agent.slug}`);
      const claims = decodeJwt(token);
      expect(claims.aud).toContain(agent.mcpUrl);
      expect(claims.manar_roles).toEqual([agent.role]);
      expect(String(claims.scope).split(' ')).toContain(agent.scopes[0]);
      expect(claims.azp).toBe(agent.clientId);
    });

    it('serves protected resource metadata naming the tenant realm', async () => {
      const res = await http().get(new URL(agent.resourceMetadataUrl).pathname);
      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        resource: agent.mcpUrl,
        authorization_servers: [issuer],
        scopes_supported: agent.scopes,
        bearer_methods_supported: ['header'],
        resource_name: 'Manar governed tools',
      });
    });

    it('401 with WWW-Authenticate resource_metadata without a token', async () => {
      const res = await mcp(path, undefined, 'tools/list');
      expect(res.status).toBe(401);
      expect(res.headers['www-authenticate']).toBe(
        `Bearer resource_metadata="${agent.resourceMetadataUrl}", scope="${agent.scopes[0]}"`,
      );
    });

    it('tools/call ALLOW runs through the governed path and DENY is refused', async () => {
      const listed = await mcp(path, token, 'tools/list');
      expect(listed.status).toBe(200);
      const allow = await mcp(path, token, 'tools/call', {
        name: 'microsoft-graph__entra.user.get',
        arguments: { resource: userId },
      });
      expect(
        (allow.body as { result: Record<string, unknown> }).result,
      ).toMatchObject({
        isError: false,
        structuredContent: { status: 'EXECUTED', outcome: 'SUCCESS' },
      });
      const deny = await mcp(path, token, 'tools/call', {
        name: 'microsoft-graph__entra.user.get',
        arguments: { resource: FIXTURE_SECOND_USER_ID },
      });
      expect(
        (deny.body as { result: Record<string, unknown> }).result,
      ).toMatchObject({
        isError: true,
        structuredContent: { status: 'DENIED', reason: 'not_authorized' },
      });
      const tenantClient = await tenants.getClient(tenantA.id);
      const decisions = await tenantClient.decision.findMany({
        where: { taskId: agent.taskId },
        orderBy: { createdAt: 'asc' },
      });
      expect(decisions.map((d) => [d.outcome, d.channel])).toEqual([
        ['ALLOW', 'MCP'],
        ['DENY', 'MCP'],
      ]);
    });

    it('a person of the realm without the agent role gets no usable token', async () => {
      const stranger = await person();
      const strangerToken = await vendorToken(copilotClient(agent), stranger);
      // Keycloak applies a client scope with role scope mappings only to holders of the role,
      // so the audience is missing; the guard's role check (user_not_allowed) is the second line.
      const claims = decodeJwt(strangerToken);
      expect(claims.aud ?? []).not.toContain(agent.mcpUrl);
      expect(claims.manar_roles).toBeUndefined();
      const res = await mcp(path, strangerToken, 'tools/list');
      expect([res.status, res.body]).toEqual([
        401,
        expect.objectContaining({ reason: 'wrong_audience' }),
      ]);
    });

    it('no password grant yields a usable token: the agent client refuses it, admin-cli lacks the audience', async () => {
      const onAgentClient = await fetch(
        `${issuer}/protocol/openid-connect/token`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'password',
            client_id: agent.clientId!,
            client_secret: agent.clientSecret!,
            username: user.username,
            password: PASSWORD,
            scope: `openid ${agent.scopes[0]}`,
          }),
        },
      );
      expect(onAgentClient.status).toBe(400);
      expect(((await onAgentClient.json()) as { error: string }).error).toBe(
        'unauthorized_client',
      );

      const adminCli = (scope: string) =>
        fetch(`${issuer}/protocol/openid-connect/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'password',
            client_id: 'admin-cli',
            username: user.username,
            password: PASSWORD,
            scope,
          }),
        });
      // admin-cli is not given the agent scope: asking for it is refused outright...
      const withScope = await adminCli(`openid ${agent.scopes[0]}`);
      expect(withScope.status).toBe(400);
      // ...and without it the token has no audience for the agent.
      const plain = await adminCli('openid');
      expect(plain.status).toBe(200);
      const adminCliToken = ((await plain.json()) as { access_token: string })
        .access_token;
      expect(decodeJwt(adminCliToken).aud ?? []).not.toContain(agent.mcpUrl);
      const before = await auditCount('wrong_audience');
      const res = await mcp(path, adminCliToken, 'tools/list');
      expect([res.status, res.body]).toEqual([
        401,
        expect.objectContaining({ reason: 'wrong_audience' }),
      ]);
      expect(res.headers['www-authenticate']).toContain(
        'error="invalid_token"',
      );
      // Signature verified: audited in the tenant.
      expect(await auditCount('wrong_audience')).toBe(before + 1);
    });

    it('refusals before the signature verifies are not audited: another tenant, unknown issuer', async () => {
      const otherUser = shortSlug('b-user');
      await createRealmUser(tenantB.keycloakRealm!, {
        username: otherUser,
        email: `${otherUser}@example.test`,
        password: PASSWORD,
      });
      const tokenB = await getUserToken({
        realm: tenantB.keycloakRealm!,
        clientId: tenantB.keycloakClientId!,
        clientSecret: await consoleSecret(tenantB),
        username: otherUser,
        password: PASSWORD,
      });
      const tenantClient = await tenants.getClient(tenantA.id);
      const before = await tenantClient.auditEvent.count();
      const cross = await mcp(path, tokenB, 'tools/list');
      expect([cross.status, cross.body]).toEqual([
        401,
        expect.objectContaining({ reason: 'issuer_tenant_mismatch' }),
      ]);
      const forged = `${Buffer.from('{"alg":"RS256"}').toString('base64url')}.${Buffer.from(
        JSON.stringify({
          iss: 'https://evil.test/realms/x',
          aud: agent.mcpUrl,
        }),
      ).toString('base64url')}.c2ln`;
      const unknown = await mcp(path, forged, 'tools/list');
      expect([unknown.status, unknown.body]).toEqual([
        401,
        expect.objectContaining({ reason: 'unknown_issuer' }),
      ]);
      const spoofed = `${token.split('.').slice(0, 2).join('.')}.c2ln`;
      const badSignature = await mcp(path, spoofed, 'tools/list');
      expect([badSignature.status, badSignature.body]).toEqual([
        401,
        expect.objectContaining({ reason: 'invalid_token' }),
      ]);
      expect(await tenantClient.auditEvent.count()).toBe(before);
    });

    it('a body over the cap is refused before it is read', async () => {
      const res = await http()
        .post(path)
        .set('Authorization', `Bearer ${token}`)
        .set('Content-Type', 'application/json')
        .send(JSON.stringify({ padding: 'x'.repeat(300_000) }));
      expect(res.status).toBe(413);
    });

    it('the callback URL and the standing task can be replaced; the client keeps its audience scope', async () => {
      const callback = 'https://global.consent.azure-apim.net/redirect/e2e';
      await http()
        .put(`/cloud-agents/${agent.agent.id}/redirect-uris`)
        .set('Authorization', admin())
        .send({ redirectUris: [COPILOT_CALLBACK, callback] })
        .expect(200);
      const [client] = await kcJson<
        {
          redirectUris: string[];
          defaultClientScopes: string[];
          directAccessGrantsEnabled: boolean;
        }[]
      >(`/admin/realms/${realm}/clients?clientId=${agent.clientId}`);
      expect(client!.redirectUris.sort()).toEqual(
        [COPILOT_CALLBACK, callback].sort(),
      );
      expect(client!.defaultClientScopes).toContain(agent.scopes[0]);
      expect(client!.directAccessGrantsEnabled).toBe(false);
      await http()
        .put(`/cloud-agents/${agent.agent.id}/redirect-uris`)
        .set('Authorization', admin())
        .send({ redirectUris: ['https://*.example.com/cb'] })
        .expect(400);

      const renewed = await http()
        .post('/tasks')
        .set('Authorization', admin())
        .send({ ...standingTask(), assignedAgentId: agent.agent.id })
        .expect(201);
      await http()
        .put(`/cloud-agents/${agent.agent.id}/task`)
        .set('Authorization', admin())
        .send({ taskId: (renewed.body as { id: string }).id })
        .expect(200);
      expect((await mcp(path, token, 'tools/list')).status).toBe(200);
      await http()
        .put(`/cloud-agents/${agent.agent.id}/task`)
        .set('Authorization', admin())
        .send({ taskId: agent.taskId })
        .expect(200);
    });

    it('the certificate APIs refuse a cloud agent', async () => {
      await http()
        .post(`/agents/${agent.agent.id}/enrollment-tokens`)
        .set('Authorization', admin())
        .expect(409);
      await http()
        .post(`/agents/${agent.agent.id}/revoke`)
        .set('Authorization', admin())
        .send({ reason: 'e2e' })
        .expect(409);
    });

    it('a quarantined cloud agent is refused', async () => {
      const tenantClient = await tenants.getClient(tenantA.id);
      await tenantClient.agentQuarantine.create({
        data: {
          agentId: agent.agent.id,
          active: true,
          reason: 'e2e',
          quarantinedByAgentId: agent.agent.id,
          quarantinedAt: new Date(),
        },
      });
      try {
        const res = await mcp(path, token, 'tools/call', {
          name: 'microsoft-graph__entra.user.get',
          arguments: { resource: userId },
        });
        expect(
          (res.body as { result: Record<string, unknown> }).result,
        ).toMatchObject({
          isError: true,
          structuredContent: { status: 'DENIED', reason: 'agent_quarantined' },
        });
      } finally {
        await tenantClient.agentQuarantine.deleteMany({
          where: { agentId: agent.agent.id },
        });
      }
    });

    it('an expired token is refused', async () => {
      await adminFetch(`/admin/realms/${realm}`, {
        method: 'PUT',
        body: JSON.stringify({ accessTokenLifespan: 1 }),
      });
      try {
        const shortLived = await vendorToken(copilotClient(agent), user);
        await new Promise((r) => setTimeout(r, 2_500));
        const res = await mcp(path, shortLived, 'tools/list');
        expect([res.status, res.body]).toEqual([
          401,
          expect.objectContaining({ reason: 'token_expired' }),
        ]);
      } finally {
        await adminFetch(`/admin/realms/${realm}`, {
          method: 'PUT',
          body: JSON.stringify({ accessTokenLifespan: 300 }),
        });
      }
    });
  });

  describe('ChatGPT (dynamic client registration)', () => {
    it('records the first registered client, refuses others, and disconnecting closes DCR', async () => {
      const agent = await connect('CHATGPT');
      expect(agent.clientId).toBeUndefined();
      const path = new URL(agent.mcpUrl).pathname;
      const register = async (redirect: string) =>
        fetch(agent.registrationUrl!, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client_name: 'ChatGPT',
            redirect_uris: [redirect],
            // A registrant may ask for the password grant; Manar turns it off when it records the client.
            grant_types: ['authorization_code', 'refresh_token', 'password'],
            response_types: ['code'],
            token_endpoint_auth_method: 'client_secret_basic',
            scope: agent.scopes[0],
          }),
        });
      expect((await register('https://evil.example/callback')).status).toBe(
        403,
      );
      const first = (await (await register(CHATGPT_CALLBACK)).json()) as {
        client_id: string;
        client_secret: string;
      };
      const second = (await (await register(CHATGPT_CALLBACK)).json()) as {
        client_id: string;
        client_secret: string;
      };

      const user = await person(agent.role);
      const tokenFor = (c: { client_id: string; client_secret: string }) =>
        vendorToken(
          {
            clientId: c.client_id,
            clientSecret: c.client_secret,
            redirectUri: CHATGPT_CALLBACK,
          },
          user,
          `openid ${agent.scopes[0]}`,
        );
      const firstToken = await tokenFor(first);
      expect(decodeJwt(firstToken).aud).toContain(agent.mcpUrl);
      expect((await mcp(path, firstToken, 'tools/list')).status).toBe(200);

      const tenantClient = await tenants.getClient(tenantA.id);
      const binding = await tenantClient.cloudAgentBinding.findUniqueOrThrow({
        where: { agentId: agent.agent.id },
      });
      expect(binding.oauthClientId).toBe(first.client_id);
      const [recorded] = await kcJson<{ directAccessGrantsEnabled: boolean }[]>(
        `/admin/realms/${realm}/clients?clientId=${first.client_id}`,
      );
      expect(recorded!.directAccessGrantsEnabled).toBe(false);

      const secondToken = await tokenFor(second);
      const refused = await mcp(path, secondToken, 'tools/list');
      expect([refused.status, refused.body]).toEqual([
        403,
        expect.objectContaining({ reason: 'unknown_client' }),
      ]);

      await http()
        .delete(`/cloud-agents/${agent.agent.id}`)
        .set('Authorization', admin())
        .send({ reason: 'e2e disconnect' })
        .expect(200);
      const after = await mcp(path, firstToken, 'tools/list');
      expect([after.status, after.body]).toEqual([
        403,
        expect.objectContaining({ reason: 'agent_not_active' }),
      ]);
      expect(
        await kcJson<unknown[]>(
          `/admin/realms/${realm}/clients?clientId=${first.client_id}`,
        ),
      ).toEqual([]);
      const scopes = await kcJson<{ name: string }[]>(
        `/admin/realms/${realm}/client-scopes`,
      );
      expect(scopes.map((s) => s.name)).not.toContain(agent.scopes[0]);
      // The last ChatGPT agent is gone: anonymous registration is closed again.
      expect((await register(CHATGPT_CALLBACK)).status).toBe(403);
    }, 60_000);
  });

  describe('connecting', () => {
    it('refuses a slug whose client name someone already took in the realm, before creating anything', async () => {
      const slug = shortSlug('sq');
      await adminFetch(`/admin/realms/${realm}/clients`, {
        method: 'POST',
        body: JSON.stringify({
          clientId: `manar-cloud-${slug}`,
          publicClient: true,
        }),
      });
      await http()
        .post('/cloud-agents')
        .set('Authorization', admin())
        .send({
          slug,
          displayName: 'squatted',
          platform: 'COPILOT_STUDIO',
          task: standingTask(),
        })
        .expect(409);
      const tenantClient = await tenants.getClient(tenantA.id);
      expect(
        await tenantClient.agent.findUnique({ where: { slug } }),
      ).toBeNull();
    });

    it('a connection that failed part way is resumed under the same slug', async () => {
      const slug = shortSlug('rs');
      const body = {
        slug,
        displayName: 'resume',
        platform: 'COPILOT_STUDIO',
        redirectUris: [COPILOT_CALLBACK],
      };
      await http()
        .post('/cloud-agents')
        .set('Authorization', admin())
        .send({ ...body, task: { ...standingTask(), packId: 'no-such-pack' } })
        .expect(403);
      const res = await http()
        .post('/cloud-agents')
        .set('Authorization', admin())
        .send({ ...body, task: standingTask() })
        .expect(201);
      expect((res.body as Connected).agent.slug).toBe(slug);
    });
  });

  describe('Entra ID brokering', () => {
    let upstream: string;
    let upstreamIssuer: string;

    beforeAll(async () => {
      const res = await http()
        .put('/cloud-agents/entra-identity-provider')
        .set('Authorization', admin())
        .send({
          directoryId: randomUUID(),
          clientId: randomUUID(),
          clientSecret: 'e2e-not-a-real-secret',
        });
      expect(res.status).toBe(200);

      // A second realm stands in for Entra ID, with the realm's broker as its client.
      upstream = shortSlug('entra');
      extraRealms.push(upstream);
      upstreamIssuer = `${KC}/realms/${upstream}`;
      await adminFetch('/admin/realms', {
        method: 'POST',
        body: JSON.stringify({ realm: upstream, enabled: true }),
      });
      await adminFetch(`/admin/realms/${upstream}/clients`, {
        method: 'POST',
        body: JSON.stringify({
          clientId: 'tenant-broker',
          secret: 'broker-secret',
          publicClient: false,
          standardFlowEnabled: true,
          redirectUris: [`${issuer}/broker/entra/endpoint`],
          protocolMappers: [
            {
              name: 'groups',
              protocol: 'openid-connect',
              protocolMapper: 'oidc-group-membership-mapper',
              config: {
                'claim.name': 'groups',
                'full.path': 'false',
                'id.token.claim': 'true',
                'access.token.claim': 'true',
                'userinfo.token.claim': 'true',
              },
            },
          ],
        }),
      });
      await app
        .get(KeycloakAdminClient)
        .upsertOidcIdentityProvider(realm, 'entra', {
          displayName: 'Upstream stand-in',
          issuer: upstreamIssuer,
          authorizationUrl: `${upstreamIssuer}/protocol/openid-connect/auth`,
          tokenUrl: `${upstreamIssuer}/protocol/openid-connect/token`,
          jwksUrl: `${upstreamIssuer}/protocol/openid-connect/certs`,
          clientId: 'tenant-broker',
          clientSecret: 'broker-secret',
        });
    }, 60_000);

    async function upstreamUser(email: string, group?: string) {
      const username = shortSlug('u');
      const res = await adminFetch(`/admin/realms/${upstream}/users`, {
        method: 'POST',
        body: JSON.stringify({
          username,
          email,
          emailVerified: true,
          firstName: 'Up',
          lastName: 'Stream',
          enabled: true,
          credentials: [
            { type: 'password', value: PASSWORD, temporary: false },
          ],
        }),
      });
      const id = res.headers.get('location')!.split('/').pop()!;
      if (group) {
        // An Entra group id arrives in the `groups` claim; here, a group named after it.
        const created = await adminFetch(`/admin/realms/${upstream}/groups`, {
          method: 'POST',
          body: JSON.stringify({ name: group }),
        });
        const groupId = created.headers.get('location')!.split('/').pop()!;
        await adminFetch(
          `/admin/realms/${upstream}/users/${id}/groups/${groupId}`,
          {
            method: 'PUT',
          },
        );
      }
      return { username, password: PASSWORD };
    }

    it('configures the provider with untrusted email and the create-only first login', async () => {
      const idp = await kcJson<{
        providerId: string;
        trustEmail: boolean;
        firstBrokerLoginFlowAlias: string;
      }>(`/admin/realms/${realm}/identity-provider/instances/entra`);
      expect(idp).toMatchObject({
        providerId: 'oidc',
        trustEmail: false,
        firstBrokerLoginFlowAlias: 'manar first broker login',
      });
      const executions = await kcJson<
        { providerId: string; requirement: string }[]
      >(
        `/admin/realms/${realm}/authentication/flows/${encodeURIComponent('manar first broker login')}/executions`,
      );
      expect(executions.map((e) => [e.providerId, e.requirement])).toEqual([
        ['idp-create-user-if-unique', 'REQUIRED'],
      ]);
    });

    it('an upstream identity with an existing user email does not get that user', async () => {
      const agent = await connect('COPILOT_STUDIO');
      const attacker = await upstreamUser(owner.email);
      const flow = await authorizationCode({
        issuer,
        clientId: agent.clientId!,
        redirectUri: COPILOT_CALLBACK,
        scope: 'openid',
        logins: [attacker],
        idpHint: 'entra',
      });
      expect('code' in flow).toBe(false);
      expect(
        await kcJson<unknown[]>(
          `/admin/realms/${realm}/users/${owner.id}/federated-identity`,
        ),
      ).toEqual([]);

      // A new person is created instead (create-only works); without the role the token has no audience.
      const newcomer = await upstreamUser(`${shortSlug('new')}@example.test`);
      const ok = await authorizationCode({
        issuer,
        clientId: agent.clientId!,
        redirectUri: COPILOT_CALLBACK,
        scope: 'openid',
        logins: [newcomer],
        idpHint: 'entra',
      });
      if (!('code' in ok)) throw new Error(describePage(ok.page));
      const token = await exchangeCode({
        issuer,
        ...copilotClient(agent),
        ...ok,
      });
      expect(decodeJwt(token).sub).not.toBe(owner.id);
      const res = await mcp(
        new URL(agent.mcpUrl).pathname,
        token,
        'tools/list',
      );
      expect([res.status, res.body]).toEqual([
        401,
        expect.objectContaining({ reason: 'wrong_audience' }),
      ]);
    }, 60_000);

    it('members of the named Entra group get the agent role on sign-in', async () => {
      const group = randomUUID();
      const agent = await connect('COPILOT_STUDIO', { entraGroupId: group });
      const member = await upstreamUser(
        `${shortSlug('m')}@example.test`,
        group,
      );
      const flow = await authorizationCode({
        issuer,
        clientId: agent.clientId!,
        redirectUri: COPILOT_CALLBACK,
        scope: 'openid',
        logins: [member],
        idpHint: 'entra',
      });
      if (!('code' in flow)) throw new Error(describePage(flow.page));
      const token = await exchangeCode({
        issuer,
        ...copilotClient(agent),
        ...flow,
      });
      expect(decodeJwt(token).manar_roles).toEqual([agent.role]);
      expect(
        (await mcp(new URL(agent.mcpUrl).pathname, token, 'tools/list')).status,
      ).toBe(200);
    }, 60_000);
  });
});
