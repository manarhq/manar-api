import 'dotenv/config';
import { vi } from 'vitest';

// The shared hosted realm as manar-infra ships it (platform/keycloak/realm-manar.yaml), imported
// into the local Keycloak under a throwaway name, with ChatGPT turned on. The endpoint is off by
// default; ConfigModule reads the environment at import time.
const shared = vi.hoisted(() => {
  const kc = process.env.KEYCLOAK_BASE_URL ?? 'http://localhost:8081';
  const realm = `manar-e2e-${Date.now().toString(36)}`;
  const issuer = `${kc}/realms/${realm}`;
  Object.assign(process.env, {
    MANAR_MCP_ENABLED: 'true',
    MANAR_MCP_HOST: 'mcp.manar.test',
    MANAR_MCP_SHARED_ISSUER: issuer,
    MANAR_MCP_CHATGPT_ENABLED: 'true',
    AUTH_ISSUERS: issuer,
    MANAR_TRUSTED_PROXY_CIDRS: '127.0.0.1/32,::1/128,::ffff:127.0.0.1/128',
  });
  return { kc, realm, issuer };
});
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { resolve } from 'node:path';
import { Client as PgClient } from 'pg';
import { loadAll } from 'js-yaml';
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
import { httpAdapterOptions } from '../src/config/trusted-proxy';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { KeycloakModule } from '../src/keycloak/keycloak.module';
import { DcrCleanupService } from '../src/cloud-mcp/dcr-cleanup.service';
import { WorkspaceProvisioningService } from '../src/workspaces/workspace-provisioning.service';
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
import {
  adminFetch,
  createRealmUser,
  deleteRealm,
} from './support/keycloak-test-helpers';
import { FakeAnalysisServiceServer } from './support/fake-analysis-service-server';
import {
  authorizationCode,
  describePage,
  exchangeCode,
} from './support/oidc-browser';
import type { Login } from './support/oidc-browser';

/**
 * ChatGPT on the shared hosted realm, end to end against a real Keycloak, the way ChatGPT does
 * it: read the protected resource metadata, find the authorization server and its registration
 * endpoint, register a client (DCR) for the advertised scope, run the authorization code flow
 * with PKCE S256 as a person, call the MCP endpoint with the token. Also: nothing works before an
 * admin confirms the client, a non-member and another workspace are refused, and the Free plan
 * allows one cloud agent. Skipped unless manar-infra is checked out next to manar-api (or
 * MANAR_INFRA_REALM_YAML points at realm-manar.yaml).
 */
const REALM_YAML = resolve(
  process.env.MANAR_INFRA_REALM_YAML ??
    '../manar-infra/platform/keycloak/realm-manar.yaml',
);

describe.skipIf(!existsSync(REALM_YAML))(
  'ChatGPT through GATE on the shared realm (e2e)',
  () => {
    const PASSWORD = 'Passw0rd!Test';
    const CONSOLE_SECRET = 'local-console-secret';
    const CONSOLE_CALLBACK = 'https://console-manar.fixio.ae/api/auth/callback';
    const CHATGPT_CALLBACK =
      'https://chatgpt.com/connector_platform_oauth_redirect';
    const { realm, issuer } = shared;
    const { userId } = MICROSOFT_FIXTURE_IDS;
    const slug = (label: string) => `gp-${label}-${randomUUID().slice(0, 8)}`;

    let app: NestFastifyApplication;
    let control: ControlPrismaService;
    let tenants: TenantDatabaseManager;
    let fixture: FastifyInstance;
    let fakeAnalysis: FakeAnalysisServiceServer;
    const tenantIds: string[] = [];

    interface Workspace {
      tenantId: string;
      slug: string;
      owner: Login & { id: string };
      adminToken: string;
    }
    let wsA: Workspace;
    let wsB: Workspace;

    const http = () => request(app.getHttpServer());

    /** The infra realm file with its secrets filled in; only the sign-in step differs locally. */
    function realmRepresentation() {
      const configMap = (
        loadAll(readFileSync(REALM_YAML, 'utf8')) as Array<{
          data?: Record<string, string>;
        } | null>
      ).find((d) => d?.data?.['manar-realm.json']);
      const json = (configMap!.data!['manar-realm.json'] as string)
        .replaceAll('${MANAR_WEB_OIDC_CLIENT_SECRET}', CONSOLE_SECRET)
        .replace(/\$\{(MICROSOFT|GITHUB)_IDP_CLIENT_(ID|SECRET)\}/g, 'unused')
        .replace(/\$\{ACS_SMTP_(USERNAME|PASSWORD)\}/g, 'unused');
      const rep = JSON.parse(json) as {
        realm: string;
        sslRequired: string;
        authenticationFlows: Array<{
          authenticationExecutions: Array<Record<string, unknown>>;
        }>;
      };
      rep.realm = realm;
      // Plain http on localhost, and a password form where the magic-link extension is not installed.
      rep.sslRequired = 'none';
      for (const flow of rep.authenticationFlows) {
        for (const step of flow.authenticationExecutions) {
          if (step.authenticator === 'skycloak-magic-link') {
            step.authenticator = 'auth-username-password-form';
            delete step.authenticatorConfig;
          }
        }
      }
      return rep;
    }

    async function person(): Promise<Login & { id: string }> {
      const username = slug('p');
      const id = await createRealmUser(realm, {
        username,
        email: `${username}@example.test`,
        password: PASSWORD,
      });
      return { id, username, password: PASSWORD };
    }

    async function workspace(label: string): Promise<Workspace> {
      const owner = await person();
      const { tenantId } = await app
        .get(WorkspaceProvisioningService)
        .createWorkspace({
          ownerSubject: owner.id,
          kind: 'PERSONAL',
          displayName: `GATE e2e ${label}`,
          ownerEmail: `${owner.username}@example.test`,
        });
      tenantIds.push(tenantId);
      const tenant = await control.tenant.findUniqueOrThrow({
        where: { id: tenantId },
      });
      // Console token: the BFF's authorization code flow with the manar-api client.
      const flow = await authorizationCode({
        issuer,
        clientId: 'manar-api',
        redirectUri: CONSOLE_CALLBACK,
        scope: 'openid',
        logins: [owner],
      });
      if (!('code' in flow)) {
        throw new Error(`No code: ${describePage(flow.page)}`);
      }
      const adminToken = await exchangeCode({
        issuer,
        clientId: 'manar-api',
        clientSecret: CONSOLE_SECRET,
        redirectUri: CONSOLE_CALLBACK,
        ...flow,
      });
      const tenantClient = await tenants.getClient(tenantId);
      const kvPath = `tools/${slug('ms')}`;
      await app
        .get(OpenBaoKvClient)
        .writeSecret(kvPath, { value: MICROSOFT_FIXTURE_APP.clientSecret });
      await ensureMicrosoftFixtureTools(tenantClient, {
        fixtureBaseUrl: (fixture as unknown as { base: string }).base,
        kvPath,
      });
      return { tenantId, slug: tenant.slug, owner, adminToken };
    }

    const standingTask = () => ({
      name: 'chatgpt standing task',
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
      mcpUrl: string;
      resourceMetadataUrl: string;
      registrationUrl: string;
      scopes: string[];
      role: string | null;
      clientId?: string;
    }
    const connect = (ws: Workspace, label = 'gpt') =>
      http()
        .post('/cloud-agents')
        .set('Authorization', `Bearer ${ws.adminToken}`)
        .set('X-Manar-Workspace', ws.tenantId)
        .send({
          slug: slug(label),
          displayName: 'ChatGPT',
          platform: 'CHATGPT',
          task: standingTask(),
        });

    /** What ChatGPT does before it has a token, from the MCP URL alone. */
    async function discover(agent: Connected) {
      const meta = await http().get(
        new URL(agent.resourceMetadataUrl).pathname,
      );
      expect(meta.status).toBe(200);
      const body = meta.body as {
        resource: string;
        authorization_servers: string[];
        scopes_supported: string[];
      };
      expect(body.resource).toBe(agent.mcpUrl);
      const as = body.authorization_servers[0]!;
      // RFC 8414 path-inserted form first (what MCP clients try), then OIDC discovery.
      const url = new URL(as);
      const rfc8414 = await fetch(
        `${url.origin}/.well-known/oauth-authorization-server${url.pathname}`,
      );
      const oidc = await fetch(`${as}/.well-known/openid-configuration`);
      const metadata = (await (rfc8414.ok ? rfc8414 : oidc).json()) as {
        registration_endpoint: string;
        code_challenge_methods_supported: string[];
      };
      return { as, scopes: body.scopes_supported, metadata };
    }

    type Registered = { client_id: string; client_secret?: string };
    const register = (
      endpoint: string,
      scope: string | undefined,
      overrides: Record<string, unknown> = {},
    ) =>
      fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'ChatGPT',
          redirect_uris: [CHATGPT_CALLBACK],
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          token_endpoint_auth_method: 'none',
          ...(scope ? { scope } : {}),
          ...overrides,
        }),
      });

    async function chatGptToken(
      client: Registered,
      who: Login,
      scope: string,
    ): Promise<string> {
      const flow = await authorizationCode({
        issuer,
        clientId: client.client_id,
        redirectUri: CHATGPT_CALLBACK,
        scope,
        logins: [who],
      });
      if (!('code' in flow)) {
        throw new Error(`No code: ${describePage(flow.page)}`);
      }
      return exchangeCode({
        issuer,
        clientId: client.client_id,
        clientSecret: client.client_secret,
        redirectUri: CHATGPT_CALLBACK,
        ...flow,
      });
    }

    let rpcId = 0;
    const mcp = (
      path: string,
      token: string | undefined,
      method: string,
      params?: unknown,
    ) => {
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
    };
    const outcome = async (path: string, token: string) => {
      const res = await mcp(path, token, 'tools/list');
      return res.status === 200
        ? 'ok'
        : `${res.status} ${(res.body as { reason?: string }).reason}`;
    };

    beforeAll(async () => {
      await adminFetch('/admin/realms', {
        method: 'POST',
        body: JSON.stringify(realmRepresentation()),
      });
      fakeAnalysis = new FakeAnalysisServiceServer();
      const analysisTarget = await fakeAnalysis.start();
      fixture = buildMicrosoftFixtureApp();
      await fixture.listen({ port: 0, host: '127.0.0.1' });
      (fixture as unknown as { base: string }).base =
        `http://127.0.0.1:${(fixture.server.address() as AddressInfo).port}`;

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
        new FastifyAdapter(httpAdapterOptions(process.env)),
      );
      await app.init();
      await app.getHttpAdapter().getInstance().ready();
      await app.listen(0, '127.0.0.1');
      control = app.get(ControlPrismaService);
      tenants = app.get(TenantDatabaseManager);
      wsA = await workspace('A');
      wsB = await workspace('B');
    }, 240_000);

    afterAll(async () => {
      await app?.close();
      await fixture?.close();
      await fakeAnalysis?.stop();
      await deleteRealm(realm);
      const pg = new PgClient({
        connectionString: process.env.CONTROL_DATABASE_URL,
      });
      await pg.connect();
      for (const id of tenantIds) {
        const binding = await control.tenantDatabaseBinding.findFirst({
          where: { tenantId: id },
        });
        if (binding?.databaseName) {
          await pg.query(
            `DROP DATABASE IF EXISTS "${binding.databaseName}" WITH (FORCE)`,
          );
        }
        await control.tenantDatabaseBinding.deleteMany({
          where: { tenantId: id },
        });
        await control.membership.deleteMany({ where: { tenantId: id } });
        await control.secretReference.deleteMany({ where: { tenantId: id } });
        await control.tenant.deleteMany({ where: { id } });
      }
      await pg.end();
    }, 60_000);

    it('anonymous registration is closed until a ChatGPT agent exists', async () => {
      const metadata = await fetch(
        `${issuer}/.well-known/openid-configuration`,
      ).then((r) => r.json() as Promise<{ registration_endpoint: string }>);
      const res = await register(metadata.registration_endpoint, undefined);
      expect(res.status).toBe(403);
    });

    describe('workspace A connects ChatGPT and ChatGPT does the OAuth dance', () => {
      let agent: Connected;
      let path: string;
      let client: Registered;
      let token: string;
      let agentB: Connected;
      let clientB: Registered;

      beforeAll(async () => {
        const res = await connect(wsA);
        expect([res.status, res.body]).toEqual([201, expect.anything()]);
        agent = res.body as Connected;
        path = new URL(agent.mcpUrl).pathname;
      }, 60_000);

      it('names the scope with the tenant id, no role, no client secret', () => {
        expect(agent.scopes).toEqual([
          `manar-mcp-${wsA.tenantId}-${agent.agent.slug}`,
        ]);
        expect(agent.role).toBeNull();
        expect(agent.clientId).toBeUndefined();
      });

      it('a tokenless call gets the 401 challenge that starts discovery, without the tenant id', async () => {
        const res = await mcp(path, undefined, 'initialize');
        expect(res.status).toBe(401);
        expect(res.headers['www-authenticate']).toContain(
          `resource_metadata="${agent.resourceMetadataUrl}"`,
        );
        expect(res.headers['www-authenticate']).not.toContain(wsA.tenantId);
      });

      it('discovery leads to a registration endpoint that accepts ChatGPT and returns a usable client', async () => {
        const found = await discover(agent);
        expect(found.as).toBe(issuer);
        expect(found.scopes).toEqual(agent.scopes);
        expect(found.metadata.code_challenge_methods_supported).toContain(
          'S256',
        );
        // Other hosts and other grants are refused.
        expect(
          (
            await register(
              found.metadata.registration_endpoint,
              found.scopes[0],
              {
                redirect_uris: ['https://evil.example/cb'],
              },
            )
          ).status,
        ).toBe(403);
        // A scope nobody offers is refused.
        expect(
          (
            await register(
              found.metadata.registration_endpoint,
              'manar-mcp-someone-else',
            )
          ).status,
        ).toBe(403);
        const res = await register(
          found.metadata.registration_endpoint,
          found.scopes[0],
        );
        expect(res.status).toBe(201);
        client = (await res.json()) as Registered;
      });

      it('a member signs in with PKCE; the token names the MCP URL, the tenant and the client', async () => {
        token = await chatGptToken(client, wsA.owner, agent.scopes[0]!);
        const claims = decodeJwt(token);
        expect(claims.iss).toBe(issuer);
        expect(claims.aud).toContain(agent.mcpUrl);
        expect(claims.manar_tenant).toBe(wsA.tenantId);
        expect(claims.azp).toBe(client.client_id);
        expect(claims.sub).toBe(wsA.owner.id);
      });

      it('the client waits for an admin: every call is refused until it is confirmed', async () => {
        expect(await outcome(path, token)).toBe(
          '403 cloud_client_pending_approval',
        );
        const shown = await http()
          .get(`/cloud-agents/${agent.agent.id}`)
          .set('Authorization', `Bearer ${wsA.adminToken}`)
          .set('X-Manar-Workspace', wsA.tenantId)
          .expect(200);
        expect(shown.body).toMatchObject({
          oauthClientId: null,
          pendingClient: {
            clientId: client.client_id,
            redirectUris: [CHATGPT_CALLBACK],
          },
        });
      });

      it('after confirmation ChatGPT initialises, lists tools and runs an allowed call; a denied one is refused', async () => {
        await http()
          .post(`/cloud-agents/${agent.agent.id}/oauth-client/confirm`)
          .set('Authorization', `Bearer ${wsA.adminToken}`)
          .set('X-Manar-Workspace', wsA.tenantId)
          .send({ clientId: client.client_id })
          .expect(201);
        const init = await mcp(path, token, 'initialize', {
          protocolVersion: '2025-06-18',
          capabilities: {},
          clientInfo: { name: 'openai-mcp', version: '1.0.0' },
        });
        expect(init.status).toBe(200);
        expect(await outcome(path, token)).toBe('ok');
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
          arguments: { resource: 'someone-else' },
        });
        expect(
          (deny.body as { result: Record<string, unknown> }).result,
        ).toMatchObject({ isError: true });
        const [confirmed] = (await (
          await adminFetch(
            `/admin/realms/${realm}/clients?clientId=${client.client_id}`,
          )
        ).json()) as Array<{
          fullScopeAllowed: boolean;
          directAccessGrantsEnabled: boolean;
          attributes: Record<string, string>;
        }>;
        expect(confirmed).toMatchObject({
          fullScopeAllowed: false,
          directAccessGrantsEnabled: false,
        });
        expect(confirmed!.attributes['pkce.code.challenge.method']).toBe(
          'S256',
        );
      });

      it('a person who is not a member of the workspace gets a token and is refused', async () => {
        const stranger = await person();
        const strangerToken = await chatGptToken(
          client,
          stranger,
          agent.scopes[0]!,
        );
        expect(await outcome(path, strangerToken)).toMatch(/^403 /);
      });

      it("another workspace's member cannot use this agent, with its own client or this one", async () => {
        // B's owner through A's confirmed client: a token with A's tenant stamp, but B is no member of A.
        const viaA = await chatGptToken(client, wsB.owner, agent.scopes[0]!);
        expect(await outcome(path, viaA)).toMatch(/^403 /);
        // B's own agent, its own client; the token is for B's MCP URL, not A's.
        const resB = await connect(wsB, 'b');
        expect(resB.status).toBe(201);
        agentB = resB.body as Connected;
        const foundB = await discover(agentB);
        clientB = (await (
          await register(
            foundB.metadata.registration_endpoint,
            foundB.scopes[0],
          )
        ).json()) as Registered;
        const tokenB = await chatGptToken(
          clientB,
          wsB.owner,
          foundB.scopes[0]!,
        );
        expect(decodeJwt(tokenB).manar_tenant).toBe(wsB.tenantId);
        expect(await outcome(path, tokenB)).toMatch(/^401 /);
      });

      it('the Free plan allows one cloud agent per workspace', async () => {
        const second = await connect(wsB, 'c');
        // Free plan: one cloud agent per workspace.
        expect(second.status).toBeGreaterThanOrEqual(400);
        expect(JSON.stringify(second.body)).toMatch(/cloudAgents|limit/i);
      });

      it('removing the membership revokes at once', async () => {
        await control.membership.updateMany({
          where: { tenantId: wsA.tenantId, subject: wsA.owner.id },
          data: { status: 'REMOVED' },
        });
        expect(await outcome(path, token)).toMatch(/^403 /);
        await control.membership.updateMany({
          where: { tenantId: wsA.tenantId, subject: wsA.owner.id },
          data: { status: 'ACTIVE' },
        });
      });

      const policyConfig = async (providerId: string) => {
        const policies = (await (
          await adminFetch(
            `/admin/realms/${realm}/components?type=org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy`,
          )
        ).json()) as Array<{
          providerId: string;
          subType: string;
          config: Record<string, string[]>;
        }>;
        return policies.find(
          (p) => p.providerId === providerId && p.subType === 'anonymous',
        )!.config;
      };

      it('anonymous registration is capped at 5000 and allows no protocol mapper type', async () => {
        expect((await policyConfig('max-clients'))['max-clients']).toEqual([
          '5000',
        ]);
        expect(
          (await policyConfig('allowed-protocol-mappers'))[
            'allowed-protocol-mapper-types'
          ] ?? [],
        ).toEqual([]);
      });

      it('a client registered with a protocol mapper (firstName onto sub) is refused, at registration and by update', async () => {
        const base = `${issuer}/clients-registrations`;
        const attack = (name: string) => ({
          clientId: name,
          publicClient: true,
          redirectUris: [CHATGPT_CALLBACK],
          standardFlowEnabled: true,
          defaultClientScopes: [agent.scopes[0]],
          protocolMappers: [
            {
              name: 'sub-override',
              protocol: 'openid-connect',
              protocolMapper: 'oidc-usermodel-property-mapper',
              config: {
                'user.attribute': 'firstName',
                'claim.name': 'sub',
                'access.token.claim': 'true',
                'jsonType.label': 'String',
              },
            },
          ],
        });
        const post = (url: string, body: unknown) =>
          fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
          });
        expect(
          (await post(`${base}/default`, attack(`evil-${slug('m')}`))).status,
        ).toBe(403);
        // Registered clean, then edited with its registration access token.
        const ok = (await (
          await post(`${base}/default`, {
            ...attack(`evil-${slug('u')}`),
            protocolMappers: [],
          })
        ).json()) as {
          clientId: string;
          registrationAccessToken: string;
        };
        const edit = await fetch(`${base}/default/${ok.clientId}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${ok.registrationAccessToken}`,
          },
          body: JSON.stringify(attack(ok.clientId)),
        });
        expect(edit.status).toBe(403);
      });

      it('a mapped client that got past the policy (made by an admin) is never proposed; a client mapped while waiting is never confirmed', async () => {
        const adminCall = (method: 'POST' | 'DELETE', suffix: string) =>
          http()
            [method === 'POST' ? 'post' : 'delete'](
              `/cloud-agents/${agent.agent.id}/${suffix}`,
            )
            .set('Authorization', `Bearer ${wsA.adminToken}`)
            .set('X-Manar-Workspace', wsA.tenantId);
        const clientRows = async (id: string) =>
          (await (
            await adminFetch(`/admin/realms/${realm}/clients?clientId=${id}`)
          ).json()) as Array<{
            id: string;
            attributes: Record<string, string>;
          }>;
        const mapper = (
          name: string,
          protocolMapper: string,
          config: object,
        ) => ({
          name,
          protocol: 'openid-connect',
          protocolMapper,
          config,
        });
        const subFromFirstName = mapper(
          'sub-override',
          'oidc-usermodel-property-mapper',
          {
            'user.attribute': 'firstName',
            'claim.name': 'sub',
            'access.token.claim': 'true',
            'jsonType.label': 'String',
          },
        );
        const adminClient = (clientId: string, protocolMappers: object[]) =>
          adminFetch(`/admin/realms/${realm}/clients`, {
            method: 'POST',
            body: JSON.stringify({
              clientId,
              publicClient: true,
              redirectUris: [CHATGPT_CALLBACK],
              standardFlowEnabled: true,
              fullScopeAllowed: false,
              // `basic` is what puts `sub` in a token; a registered client gets it by default.
              defaultClientScopes: protocolMappers.length
                ? [agent.scopes[0]]
                : ['basic', agent.scopes[0]],
              protocolMappers,
            }),
          });

        // Free the binding (reject the confirmed client) so the next client is judged on its own.
        await adminCall('DELETE', 'oauth-client').expect(200);
        expect(await clientRows(client.client_id)).toEqual([]);

        // The attacker edits their own firstName to the victim's id; the client maps it onto sub.
        const attacker = await person();
        await adminFetch(`/admin/realms/${realm}/users/${attacker.id}`, {
          method: 'PUT',
          body: JSON.stringify({ firstName: wsA.owner.id }),
        });
        const evilId = `evil-${slug('a')}`;
        await adminClient(evilId, [subFromFirstName]);
        const evilToken = await chatGptToken(
          { client_id: evilId },
          attacker,
          agent.scopes[0]!,
        );
        // The token really does say sub = the victim member; the client check is the control.
        expect(decodeJwt(evilToken).sub).toBe(wsA.owner.id);
        expect(await outcome(path, evilToken)).toBe('403 unknown_client');
        const shown = await http()
          .get(`/cloud-agents/${agent.agent.id}`)
          .set('Authorization', `Bearer ${wsA.adminToken}`)
          .set('X-Manar-Workspace', wsA.tenantId)
          .expect(200);
        expect(shown.body).toMatchObject({ pendingClient: null });

        // A clean client is proposed; a mapper added while it waits blocks the confirmation.
        const waitingId = `waiting-${slug('w')}`;
        await adminClient(waitingId, []);
        const waitingToken = await chatGptToken(
          { client_id: waitingId },
          wsA.owner,
          agent.scopes[0]!,
        );
        expect(await outcome(path, waitingToken)).toBe(
          '403 cloud_client_pending_approval',
        );
        const [row] = await clientRows(waitingId);
        expect(row!.attributes['manar.dcr.state']).toBe('pending');
        await adminFetch(
          `/admin/realms/${realm}/clients/${row!.id}/protocol-mappers/models`,
          {
            method: 'POST',
            body: JSON.stringify(
              mapper('late', 'oidc-hardcoded-claim-mapper', {
                'claim.name': 'x',
                'claim.value': 'y',
              }),
            ),
          },
        );
        await adminCall('POST', 'oauth-client/confirm')
          .send({ clientId: waitingId })
          .expect(409);

        // Reset deletes every client carrying the agent's scope, public ones included.
        await adminCall('DELETE', 'oauth-client').expect(200);
        for (const id of [evilId, waitingId]) {
          expect(await clientRows(id)).toEqual([]);
        }

        // The real connector registers again and is confirmed; service is restored.
        client = (await (
          await register(agent.registrationUrl, agent.scopes[0])
        ).json()) as Registered;
        token = await chatGptToken(client, wsA.owner, agent.scopes[0]!);
        expect(await outcome(path, token)).toBe(
          '403 cloud_client_pending_approval',
        );
        await adminCall('POST', 'oauth-client/confirm')
          .send({ clientId: client.client_id })
          .expect(201);
        expect(await outcome(path, token)).toBe('ok');
        const [confirmed] = await clientRows(client.client_id);
        expect(confirmed!.attributes['manar.dcr.state']).toBe('confirmed');
      });

      it('registrations that ask for no agent scope are swept after 15 minutes, waiting and confirmed clients never', async () => {
        const stray = (await (
          await register(agent.registrationUrl, undefined)
        ).json()) as Registered;
        const clientsNow = async () =>
          (await (
            await adminFetch(`/admin/realms/${realm}/clients?max=5000`)
          ).json()) as Array<{
            clientId: string;
            attributes: Record<string, string>;
          }>;
        expect(
          (await clientsNow()).some((c) => c.clientId === stray.client_id),
        ).toBe(true);
        const sweeper = app.get(DcrCleanupService);
        const t0 = Date.now();
        await sweeper.sweep(t0);
        expect(await sweeper.sweep(t0 + 14 * 60_000)).toEqual([]);
        expect(await sweeper.sweep(t0 + 16 * 60_000)).toEqual([
          stray.client_id,
        ]);
        const left = (await clientsNow()).map((c) => c.clientId);
        expect(left).not.toContain(stray.client_id);
        expect(left).toContain(client.client_id);
        expect(
          (await clientsNow()).find((c) => c.clientId === client.client_id)!
            .attributes['manar.dcr.state'],
        ).toBe('confirmed');
      });

      it('rejecting and disconnecting delete public clients too; the last disconnect closes registration', async () => {
        const gone = async (id: string) =>
          (await (
            await adminFetch(`/admin/realms/${realm}/clients?clientId=${id}`)
          ).json()) as unknown[];
        // B's connector registered a public client earlier.
        expect(await gone(clientB.client_id)).toHaveLength(1);
        await http()
          .delete(`/cloud-agents/${agentB.agent.id}/oauth-client`)
          .set('Authorization', `Bearer ${wsB.adminToken}`)
          .set('X-Manar-Workspace', wsB.tenantId)
          .expect(200);
        expect(await gone(clientB.client_id)).toEqual([]);
        const foundB = (await (
          await register(agentB.registrationUrl, agentB.scopes[0])
        ).json()) as Registered;
        expect(await gone(foundB.client_id)).toHaveLength(1);
        await http()
          .delete(`/cloud-agents/${agentB.agent.id}`)
          .set('Authorization', `Bearer ${wsB.adminToken}`)
          .set('X-Manar-Workspace', wsB.tenantId)
          .send({ reason: 'e2e' })
          .expect(200);
        expect(await gone(foundB.client_id)).toEqual([]);
        // A's agent is still connected, so registration stays open for it; disconnecting it closes it.
        expect(
          (await register(agent.registrationUrl, agent.scopes[0])).status,
        ).toBe(201);
        await http()
          .delete(`/cloud-agents/${agent.agent.id}`)
          .set('Authorization', `Bearer ${wsA.adminToken}`)
          .set('X-Manar-Workspace', wsA.tenantId)
          .send({ reason: 'e2e' })
          .expect(200);
        expect(await gone(client.client_id)).toEqual([]);
        expect((await register(agent.registrationUrl, undefined)).status).toBe(
          403,
        );
      });
    });
  },
);
