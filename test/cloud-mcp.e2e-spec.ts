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

/**
 * docs/cloud-agents.md end to end against a real Keycloak: connect a Copilot
 * Studio agent and a ChatGPT agent, discovery, the OAuth gate (401 with
 * WWW-Authenticate, wrong audience, cross-tenant, expiry), and the governed
 * tools/call path (ALLOW, DENY, quarantine) through the public endpoint.
 *
 * Tokens come from real Keycloak grants. Copilot Studio and ChatGPT use the
 * authorization code flow; this suite turns on the password grant on the
 * agent's client (test only) to mint the same access token without a browser.
 */
describe('Cloud agents: public MCP with OAuth (e2e)', () => {
  const HOST = 'mcp.manar.test';
  const USER_PASSWORD = 'Passw0rd!Test';
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
  let ownerToken: string;
  let username: string;

  const http = () => request(app.getHttpServer());

  async function cleanupTenant(t: Tenant): Promise<void> {
    if (t.keycloakRealm) await deleteRealm(t.keycloakRealm);
    if (t.databaseBinding?.databaseName) {
      const admin = new PgClient({
        connectionString: process.env.CONTROL_DATABASE_URL,
      });
      await admin.connect();
      await admin.query(
        `DROP DATABASE IF EXISTS "${t.databaseBinding.databaseName}" WITH (FORCE)`,
      );
      await admin.end();
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

  /** Test only: the password grant on a realm client, so a token needs no browser. */
  async function enablePasswordGrant(realm: string, clientId: string) {
    const [client] = (await (
      await adminFetch(
        `/admin/realms/${realm}/clients?clientId=${encodeURIComponent(clientId)}`,
      )
    ).json()) as Array<Record<string, unknown> & { id: string }>;
    await adminFetch(`/admin/realms/${realm}/clients/${client!.id}`, {
      method: 'PUT',
      body: JSON.stringify({
        ...client,
        directAccessGrantsEnabled: true,
        consentRequired: false,
      }),
    });
    return client!.id;
  }

  async function passwordToken(
    realm: string,
    clientId: string,
    clientSecret: string,
    scope: string,
  ) {
    const res = await fetch(
      `${process.env.KEYCLOAK_BASE_URL}/realms/${realm}/protocol/openid-connect/token`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          // client_secret_basic: what a DCR client registered with by default.
          Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
        },
        body: new URLSearchParams({
          grant_type: 'password',
          username,
          password: USER_PASSWORD,
          scope,
        }),
      },
    );
    const body = (await res.json()) as Record<string, string>;
    expect([res.status, body.error_description]).toEqual([200, undefined]);
    return body.access_token!;
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

    username = shortSlug('owner');
    const id = await createRealmUser(tenantA.keycloakRealm!, {
      username,
      email: `${username}@example.test`,
      password: USER_PASSWORD,
    });
    await assignRealmRole(tenantA.keycloakRealm!, id, 'TENANT_OWNER');
    ownerToken = await getUserToken({
      realm: tenantA.keycloakRealm!,
      clientId: tenantA.keycloakClientId!,
      clientSecret: await consoleSecret(tenantA),
      username,
      password: USER_PASSWORD,
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

  async function connect(platform: 'COPILOT_STUDIO' | 'CHATGPT') {
    const res = await http()
      .post('/cloud-agents')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        slug: shortSlug(platform === 'CHATGPT' ? 'gpt' : 'cs'),
        displayName: `Cloud ${platform}`,
        platform,
        task: standingTask(),
      });
    expect(res.status).toBe(201);
    return res.body as {
      agent: { id: string; slug: string };
      taskId: string;
      mcpUrl: string;
      resourceMetadataUrl: string;
      authorizationServer: string;
      tokenUrl: string;
      scopes: string[];
      clientId?: string;
      clientSecret?: string;
      registrationUrl?: string;
    };
  }

  describe('Copilot Studio (pre-registered client)', () => {
    let agent: Awaited<ReturnType<typeof connect>>;
    let path: string;
    let token: string;

    beforeAll(async () => {
      agent = await connect('COPILOT_STUDIO');
      path = new URL(agent.mcpUrl).pathname;
      await enablePasswordGrant(tenantA.keycloakRealm!, agent.clientId!);
      token = await passwordToken(
        tenantA.keycloakRealm!,
        agent.clientId!,
        agent.clientSecret!,
        'openid',
      );
    }, 60_000);

    it('returns what the admin pastes into Copilot Studio, and a token carries the MCP URL as audience', () => {
      expect(agent.mcpUrl).toBe(
        `https://${HOST}/mcp/${tenantA.slug}/${agent.agent.slug}`,
      );
      expect(agent.authorizationServer).toBe(tenantA.keycloakIssuerUrl);
      expect(agent.tokenUrl).toBe(
        `${tenantA.keycloakIssuerUrl}/protocol/openid-connect/token`,
      );
      expect(agent.clientId).toBe(`manar-cloud-${agent.agent.slug}`);
      expect(agent.clientSecret).toEqual(expect.any(String));
      const claims = decodeJwt(token);
      expect(claims.aud).toContain(agent.mcpUrl);
      expect(String(claims.scope).split(' ')).toContain(agent.scopes[0]);
      expect(claims.azp).toBe(agent.clientId);
    });

    it('serves protected resource metadata naming the tenant realm', async () => {
      const res = await http().get(new URL(agent.resourceMetadataUrl).pathname);
      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        resource: agent.mcpUrl,
        authorization_servers: [tenantA.keycloakIssuerUrl],
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

    it('tools/list shows the standing task tools', async () => {
      const res = await mcp(path, token, 'tools/list');
      expect(res.status).toBe(200);
      const names = (
        res.body as { result: { tools: { name: string }[] } }
      ).result.tools.map((t) => t.name);
      expect(names).toContain('microsoft-graph__entra.user.get');
    });

    it('tools/call ALLOW runs through the governed path and DENY is refused', async () => {
      const allow = await mcp(path, token, 'tools/call', {
        name: 'microsoft-graph__entra.user.get',
        arguments: { resource: userId },
      });
      expect(allow.status).toBe(200);
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

    it('the callback URL and the standing task can be replaced; the client keeps its audience scope', async () => {
      const callback = 'https://global.consent.azure-apim.net/redirect/e2e';
      await http()
        .put(`/cloud-agents/${agent.agent.id}/redirect-uris`)
        .set('Authorization', `Bearer ${ownerToken}`)
        .send({ redirectUris: [callback] })
        .expect(200);
      const [client] = (await (
        await adminFetch(
          `/admin/realms/${tenantA.keycloakRealm}/clients?clientId=${agent.clientId}`,
        )
      ).json()) as { redirectUris: string[]; defaultClientScopes: string[] }[];
      expect(client!.redirectUris).toEqual([callback]);
      expect(client!.defaultClientScopes).toContain(agent.scopes[0]);
      await http()
        .put(`/cloud-agents/${agent.agent.id}/redirect-uris`)
        .set('Authorization', `Bearer ${ownerToken}`)
        .send({ redirectUris: ['https://*.example.com/cb'] })
        .expect(400);

      const renewed = await http()
        .post('/tasks')
        .set('Authorization', `Bearer ${ownerToken}`)
        .send({ ...standingTask(), assignedAgentId: agent.agent.id })
        .expect(201);
      const renewedId = (renewed.body as { id: string }).id;
      await http()
        .put(`/cloud-agents/${agent.agent.id}/task`)
        .set('Authorization', `Bearer ${ownerToken}`)
        .send({ taskId: renewedId })
        .expect(200);
      const listed = await mcp(path, token, 'tools/list');
      expect(listed.status).toBe(200);
      await http()
        .put(`/cloud-agents/${agent.agent.id}/task`)
        .set('Authorization', `Bearer ${ownerToken}`)
        .send({ taskId: agent.taskId })
        .expect(200);
    });

    it('401 for a token of the right realm but another audience (the console client), audited', async () => {
      const consoleToken = await getUserToken({
        realm: tenantA.keycloakRealm!,
        clientId: tenantA.keycloakClientId!,
        clientSecret: await consoleSecret(tenantA),
        username,
        password: USER_PASSWORD,
      });
      const res = await mcp(path, consoleToken, 'tools/list');
      expect(res.status).toBe(401);
      expect(res.body).toMatchObject({ reason: 'wrong_audience' });
      expect(res.headers['www-authenticate']).toContain(
        'error="invalid_token"',
      );
      const tenantClient = await tenants.getClient(tenantA.id);
      const event = await tenantClient.auditEvent.findFirstOrThrow({
        where: { eventType: 'cloud_mcp.token_rejected' },
        orderBy: { sequence: 'desc' },
      });
      expect(event.data).toMatchObject({ reason: 'wrong_audience' });
      expect(JSON.stringify(event.data)).not.toContain(consoleToken);
    });

    it('401 for another tenant’s token on this tenant’s path, and for an unknown issuer', async () => {
      const otherUser = shortSlug('b-user');
      await createRealmUser(tenantB.keycloakRealm!, {
        username: otherUser,
        email: `${otherUser}@example.test`,
        password: USER_PASSWORD,
      });
      const tokenB = await getUserToken({
        realm: tenantB.keycloakRealm!,
        clientId: tenantB.keycloakClientId!,
        clientSecret: await consoleSecret(tenantB),
        username: otherUser,
        password: USER_PASSWORD,
      });
      const cross = await mcp(path, tokenB, 'tools/list');
      expect(cross.status).toBe(401);
      expect(cross.body).toMatchObject({ reason: 'issuer_tenant_mismatch' });

      const forged = `${Buffer.from('{"alg":"RS256"}').toString('base64url')}.${Buffer.from(
        JSON.stringify({
          iss: 'https://evil.test/realms/x',
          aud: agent.mcpUrl,
        }),
      ).toString('base64url')}.c2ln`;
      const unknown = await mcp(path, forged, 'tools/list');
      expect(unknown.status).toBe(401);
      expect(unknown.body).toMatchObject({ reason: 'unknown_issuer' });
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
      const realm = tenantA.keycloakRealm!;
      await adminFetch(`/admin/realms/${realm}`, {
        method: 'PUT',
        body: JSON.stringify({ accessTokenLifespan: 1 }),
      });
      const shortLived = await passwordToken(
        realm,
        agent.clientId!,
        agent.clientSecret!,
        'openid',
      );
      await new Promise((r) => setTimeout(r, 2_500));
      const res = await mcp(path, shortLived, 'tools/list');
      expect(res.status).toBe(401);
      expect(res.body).toMatchObject({ reason: 'token_expired' });
      await adminFetch(`/admin/realms/${realm}`, {
        method: 'PUT',
        body: JSON.stringify({ accessTokenLifespan: 300 }),
      });
    });
  });

  describe('ChatGPT (dynamic client registration)', () => {
    it('opens DCR to ChatGPT redirect URIs only, and a registered client reaches only its agent', async () => {
      const agent = await connect('CHATGPT');
      expect(agent.clientId).toBeUndefined();
      expect(agent.registrationUrl).toBe(
        `${tenantA.keycloakIssuerUrl}/clients-registrations/openid-connect`,
      );

      const register = (redirect: string) =>
        fetch(agent.registrationUrl!, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client_name: 'ChatGPT',
            redirect_uris: [redirect],
            grant_types: ['authorization_code', 'refresh_token'],
            response_types: ['code'],
            token_endpoint_auth_method: 'client_secret_basic',
            // A client scope of the realm only: "openid" is not one, and Keycloak's
            // anonymous Allowed Client Scopes policy refuses names it does not know.
            scope: agent.scopes[0],
          }),
        });
      const refused = await register('https://evil.example/callback');
      expect(refused.status).toBe(403);
      const registered = await register(
        'https://chatgpt.com/connector_platform_oauth_redirect',
      );
      expect(registered.status).toBe(201);
      const client = (await registered.json()) as {
        client_id: string;
        client_secret: string;
      };

      await enablePasswordGrant(tenantA.keycloakRealm!, client.client_id);
      const token = await passwordToken(
        tenantA.keycloakRealm!,
        client.client_id,
        client.client_secret,
        `openid ${agent.scopes[0]}`,
      );
      expect(decodeJwt(token).aud).toContain(agent.mcpUrl);
      const path = new URL(agent.mcpUrl).pathname;
      const ok = await mcp(path, token, 'tools/list');
      expect([ok.status, ok.body]).toEqual([200, expect.anything()]);

      // The same token on another agent's path: wrong audience.
      const other = await mcp(
        `/mcp/${tenantA.slug}/someone-else`,
        token,
        'tools/list',
      );
      expect(other.status).toBe(401);
    });
  });

  it('configures the realm’s Entra ID identity provider (TENANT_OWNER)', async () => {
    const directoryId = randomUUID();
    const res = await http()
      .put('/cloud-agents/entra-identity-provider')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        directoryId,
        clientId: randomUUID(),
        clientSecret: 'e2e-not-a-real-secret',
      });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      alias: 'entra',
      redirectUri: `${tenantA.keycloakIssuerUrl}/broker/entra/endpoint`,
    });
    const idp = (await (
      await adminFetch(
        `/admin/realms/${tenantA.keycloakRealm}/identity-provider/instances/entra`,
      )
    ).json()) as { providerId: string; config: Record<string, string> };
    expect(idp.providerId).toBe('oidc');
    expect(idp.config).toMatchObject({
      issuer: `https://login.microsoftonline.com/${directoryId}/v2.0`,
      jwksUrl: `https://login.microsoftonline.com/${directoryId}/discovery/v2.0/keys`,
      useJwksUrl: 'true',
      validateSignature: 'true',
      pkceEnabled: 'true',
    });
  });
});
