import { HttpException, type ExecutionContext } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import type { ThrottlerStorage } from '@nestjs/throttler';
import { generateKeyPair, SignJWT, type JWTVerifyGetKey } from 'jose';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../audit/audit.service';
import type { JwksCacheService } from '../auth/jwks-cache.service';
import type { KnownIssuerRegistry } from '../auth/known-issuer-registry.service';
import type { AppConfig } from '../config/env.validation';
import type { ControlPrismaService } from '../database/control-prisma.service';
import type { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import {
  CloudMcpAuthGuard,
  type CloudMcpRequest,
} from './cloud-mcp-auth.guard';
import { CloudMcpController } from './cloud-mcp.controller';

/**
 * The OAuth gate of the public MCP endpoint, with fabricated tokens signed by
 * a test key (the real-Keycloak path is test/cloud-mcp.e2e-spec.ts).
 */

const HOST = 'mcp.manar.test';
const ISSUER = 'https://id.manar.test/realms/acme';
const OTHER_ISSUER = 'https://id.manar.test/realms/globex';
const MCP_URL = `https://${HOST}/mcp/acme/copilot-1`;
const METADATA_URL = `https://${HOST}/.well-known/oauth-protected-resource/mcp/acme/copilot-1`;
const SCOPE = 'manar-mcp-copilot-1';

let signingKey: CryptoKey;
let jwks: JWTVerifyGetKey;

beforeAll(async () => {
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  signingKey = privateKey;
  jwks = () => Promise.resolve(publicKey);
});

async function token(
  overrides: Record<string, unknown> = {},
  options: { issuer?: string; expiresIn?: string; aud?: string } = {},
) {
  return new SignJWT({
    typ: 'Bearer',
    azp: 'manar-cloud-copilot-1',
    scope: `openid profile ${SCOPE}`,
    sub: 'user-1',
    ...overrides,
  })
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuer(options.issuer ?? ISSUER)
    .setAudience(options.aud ?? MCP_URL)
    .setIssuedAt()
    .setExpirationTime(options.expiresIn ?? '5m')
    .sign(signingKey);
}

interface Agent {
  id: string;
  slug: string;
  identifier: string;
  kind: string;
  status: string;
  cloudBinding: {
    oauthClientId: string | null;
    oauthScope: string;
    taskId: string;
  } | null;
}

function cloudAgent(overrides: Partial<Agent> = {}): Agent {
  return {
    id: 'agent-1',
    slug: 'copilot-1',
    identifier: 'agent://acme/copilot-1',
    kind: 'CLOUD',
    status: 'ACTIVE',
    cloudBinding: {
      oauthClientId: 'manar-cloud-copilot-1',
      oauthScope: SCOPE,
      taskId: 'task-1',
    },
    ...overrides,
  };
}

function setup(
  options: {
    agent?: Agent | null;
    env?: Record<string, unknown>;
    blocked?: boolean;
  } = {},
) {
  const env: Record<string, unknown> = {
    MANAR_MCP_ENABLED: 'true',
    MANAR_MCP_HOST: HOST,
    KEYCLOAK_CLIENT_ID: 'manar-api',
    ...options.env,
  };
  const config = {
    get: (key: string) => env[key],
  } as unknown as ConfigService<AppConfig, true>;
  const issuers: Record<string, { tenantId: string; tenantSlug: string }> = {
    [ISSUER]: { tenantId: 't-acme', tenantSlug: 'acme' },
    [OTHER_ISSUER]: { tenantId: 't-globex', tenantSlug: 'globex' },
  };
  const knownIssuers = {
    resolveByIssuer: (iss: string) =>
      Promise.resolve(
        issuers[iss] ? { ...issuers[iss], issuerUrl: iss } : null,
      ),
  } as unknown as KnownIssuerRegistry;
  const jwksCache = { getJwks: () => jwks } as unknown as JwksCacheService;
  const control = {
    tenant: {
      findUnique: () => Promise.resolve({ id: 't-acme', status: 'ACTIVE' }),
    },
  } as unknown as ControlPrismaService;
  const tenantClient = {
    agent: {
      findUnique: () =>
        Promise.resolve(
          options.agent === undefined ? cloudAgent() : options.agent,
        ),
    },
  };
  const tenants = {
    getClient: () => Promise.resolve(tenantClient),
  } as unknown as TenantDatabaseManager;
  const recordSafely = vi.fn().mockResolvedValue(undefined);
  const audit = { recordSafely } as unknown as AuditService;
  const increment = vi.fn().mockResolvedValue({
    totalHits: 1,
    timeToExpire: 60,
    isBlocked: options.blocked ?? false,
    timeToBlockExpire: options.blocked ? 30 : 0,
  });
  const limits = { increment } as unknown as ThrottlerStorage;
  const guard = new CloudMcpAuthGuard(
    config,
    knownIssuers,
    jwksCache,
    control,
    tenants,
    audit,
    limits,
  );
  return { guard, config, control, recordSafely, increment };
}

function context(
  authorization?: string,
  params: Record<string, string> = {
    tenantSlug: 'acme',
    agentSlug: 'copilot-1',
  },
  headers: Record<string, string> = {},
) {
  const request = {
    params,
    headers: { ...headers, ...(authorization ? { authorization } : {}) },
  } as unknown as CloudMcpRequest;
  const replyHeaders: Record<string, string> = {};
  const reply = {
    header: (name: string, value: string) => {
      replyHeaders[name] = value;
      return reply;
    },
  };
  const ctx = {
    switchToHttp: () => ({
      getRequest: () => request,
      getResponse: () => reply,
    }),
  } as unknown as ExecutionContext;
  return { ctx, request, replyHeaders };
}

async function refusal(promise: Promise<unknown>) {
  const error = await promise.then(
    () => {
      throw new Error('expected a refusal');
    },
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(HttpException);
  const http = error as HttpException;
  return {
    status: http.getStatus(),
    body: http.getResponse() as Record<string, unknown>,
  };
}

describe('CloudMcpAuthGuard', () => {
  let s: ReturnType<typeof setup>;
  beforeEach(() => {
    s = setup();
  });

  it('accepts a token for this agent and attaches its context and standing task', async () => {
    const { ctx, request } = context(`Bearer ${await token()}`);
    await expect(s.guard.canActivate(ctx)).resolves.toBe(true);
    expect(request.cloudAgent).toEqual({
      taskId: 'task-1',
      context: {
        tenant: { id: 't-acme', slug: 'acme' },
        agent: {
          id: 'agent-1',
          slug: 'copilot-1',
          identifier: 'agent://acme/copilot-1',
        },
      },
    });
    expect(s.increment).toHaveBeenCalledWith(
      'cloud-mcp:t-acme:agent-1',
      60_000,
      60,
      60_000,
      'cloud-mcp',
    );
    expect(s.recordSafely).not.toHaveBeenCalled();
  });

  it('401 with WWW-Authenticate naming the metadata and scope when no token; not audited', async () => {
    const { ctx, replyHeaders } = context();
    const { status } = await refusal(s.guard.canActivate(ctx));
    expect(status).toBe(401);
    expect(replyHeaders['WWW-Authenticate']).toBe(
      `Bearer resource_metadata="${METADATA_URL}", scope="${SCOPE}"`,
    );
    expect(s.recordSafely).not.toHaveBeenCalled();
  });

  it.each([
    [
      'unknown issuer',
      () => token({}, { issuer: 'https://evil.test/realms/acme' }),
      'unknown_issuer',
    ],
    [
      'another tenant’s issuer on this tenant’s path',
      () => token({}, { issuer: OTHER_ISSUER }),
      'issuer_tenant_mismatch',
    ],
    [
      'wrong audience',
      () => token({}, { aud: 'https://mcp.manar.test/mcp/acme/other' }),
      'wrong_audience',
    ],
    ['expired', () => token({}, { expiresIn: '-1s' }), 'token_expired'],
    ['an ID token', () => token({ typ: 'ID' }), 'not_an_access_token'],
    ['garbage', () => Promise.resolve('not-a-jwt'), 'unknown_issuer'],
  ])(
    '401 invalid_token for %s, audited without the token',
    async (_label, make, reason) => {
      const raw = await make();
      const { ctx, replyHeaders } = context(`Bearer ${raw}`);
      const { status, body } = await refusal(s.guard.canActivate(ctx));
      expect(status).toBe(401);
      expect(body.reason).toBe(reason);
      expect(replyHeaders['WWW-Authenticate']).toContain(
        'error="invalid_token"',
      );
      expect(replyHeaders['WWW-Authenticate']).toContain(
        `resource_metadata="${METADATA_URL}"`,
      );
      expect(s.recordSafely).toHaveBeenCalledTimes(1);
      const [, tenantId, event] = s.recordSafely.mock.calls[0] as [
        unknown,
        string,
        { eventType: string; data: Record<string, unknown> },
      ];
      expect(tenantId).toBe('t-acme');
      expect(event.eventType).toBe('cloud_mcp.token_rejected');
      expect(event.data.reason).toBe(reason);
      expect(JSON.stringify(event)).not.toContain(raw);
    },
  );

  it.each([
    ['another client', { azp: 'some-other-client' }],
    ['the scope missing', { scope: 'openid profile' }],
  ])('403 unknown_client for %s', async (_label, claims) => {
    const { ctx, replyHeaders } = context(`Bearer ${await token(claims)}`);
    const { status, body } = await refusal(s.guard.canActivate(ctx));
    expect(status).toBe(403);
    expect(body.reason).toBe('unknown_client');
    expect(replyHeaders['WWW-Authenticate']).toContain(
      'error="insufficient_scope"',
    );
  });

  it('403 for an agent that is not a cloud agent, does not exist, or is not active', async () => {
    for (const [agent, reason] of [
      [cloudAgent({ kind: 'WORKLOAD', cloudBinding: null }), 'unknown_agent'],
      [null, 'unknown_agent'],
      [cloudAgent({ status: 'REVOKED' }), 'agent_not_active'],
    ] as const) {
      const { ctx } = context(`Bearer ${await token()}`);
      const { status, body } = await refusal(
        setup({ agent }).guard.canActivate(ctx),
      );
      expect([status, body.reason]).toEqual([403, reason]);
    }
  });

  it('a DCR (ChatGPT) agent accepts a self-registered client, not the console client or another agent client', async () => {
    const dcr = cloudAgent({
      cloudBinding: {
        oauthClientId: null,
        oauthScope: SCOPE,
        taskId: 'task-1',
      },
    });
    const { guard } = setup({ agent: dcr });
    const ok = context(
      `Bearer ${await token({ azp: 'a1b2-registered-by-chatgpt' })}`,
    );
    await expect(guard.canActivate(ok.ctx)).resolves.toBe(true);
    const consoleToken = context(`Bearer ${await token({ azp: 'manar-api' })}`);
    expect((await refusal(guard.canActivate(consoleToken.ctx))).status).toBe(
      403,
    );
    const otherAgents = context(
      `Bearer ${await token({ azp: 'manar-cloud-another-agent' })}`,
    );
    expect((await refusal(guard.canActivate(otherAgents.ctx))).status).toBe(
      403,
    );
  });

  it('429 with Retry-After over the per-agent limit', async () => {
    const { ctx, replyHeaders } = context(`Bearer ${await token()}`);
    const { status } = await refusal(
      setup({ blocked: true }).guard.canActivate(ctx),
    );
    expect(status).toBe(429);
    expect(replyHeaders['Retry-After']).toBe('30');
  });

  it('413 over the body cap, 404 when the endpoint is off or the path is not a slug pair', async () => {
    const big = context(undefined, undefined, { 'content-length': '300000' });
    expect((await refusal(s.guard.canActivate(big.ctx))).status).toBe(413);
    const off = setup({ env: { MANAR_MCP_ENABLED: 'false' } });
    expect((await refusal(off.guard.canActivate(context().ctx))).status).toBe(
      404,
    );
    const bad = context(undefined, { tenantSlug: 'ACME', agentSlug: 'x' });
    expect((await refusal(s.guard.canActivate(bad.ctx))).status).toBe(404);
  });
});

describe('CloudMcpController protected resource metadata', () => {
  it('names the tenant realm as the authorization server and the agent scope', async () => {
    const { config } = setup();
    const control = {
      tenant: {
        findUnique: () =>
          Promise.resolve({ status: 'ACTIVE', keycloakIssuerUrl: ISSUER }),
      },
    } as unknown as ControlPrismaService;
    const controller = new CloudMcpController(config, control, {} as never);
    await expect(
      controller.protectedResourceMetadata('acme', 'copilot-1'),
    ).resolves.toEqual({
      resource: MCP_URL,
      authorization_servers: [ISSUER],
      scopes_supported: [SCOPE],
      bearer_methods_supported: ['header'],
      resource_name: 'Manar governed tools',
    });
    const gone = new CloudMcpController(
      config,
      { tenant: { findUnique: () => Promise.resolve(null) } } as never,
      {} as never,
    );
    await expect(gone.protectedResourceMetadata('nope', 'x')).rejects.toThrow();
  });
});
