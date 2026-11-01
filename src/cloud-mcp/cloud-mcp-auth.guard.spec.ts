import {
  ForbiddenException,
  HttpException,
  type ExecutionContext,
} from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import type { ThrottlerStorage } from '@nestjs/throttler';
import { generateKeyPair, SignJWT, type JWTVerifyGetKey } from 'jose';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../audit/audit.service';
import type { JwksCacheService } from '../auth/jwks-cache.service';
import type { KnownIssuerRegistry } from '../auth/known-issuer-registry.service';
import type { MembershipService } from '../auth/membership.service';
import type { AppConfig } from '../config/env.validation';
import type { ControlPrismaService } from '../database/control-prisma.service';
import type { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { registry } from '../metrics/metrics';
import type { CloudAgentsService } from './cloud-agents.service';
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
const ROLE = 'manar-agent-copilot-1';

let signingKey: CryptoKey;
let strangerKey: CryptoKey;
let jwks: JWTVerifyGetKey;

beforeAll(async () => {
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  signingKey = privateKey;
  strangerKey = (await generateKeyPair('RS256')).privateKey;
  jwks = () => Promise.resolve(publicKey);
});

async function token(
  overrides: Record<string, unknown> = {},
  options: {
    issuer?: string;
    expiresIn?: string;
    aud?: string | string[];
    key?: CryptoKey;
  } = {},
) {
  return new SignJWT({
    typ: 'Bearer',
    azp: 'manar-cloud-copilot-1',
    scope: `openid profile ${SCOPE}`,
    manar_roles: [ROLE],
    sub: 'user-1',
    ...overrides,
  })
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuer(options.issuer ?? ISSUER)
    .setAudience(options.aud ?? MCP_URL)
    .setIssuedAt()
    .setExpirationTime(options.expiresIn ?? '5m')
    .sign(options.key ?? signingKey);
}

interface Agent {
  id: string;
  slug: string;
  identifier: string;
  kind: string;
  status: string;
  cloudBinding: {
    platform: string;
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
      platform: 'COPILOT_STUDIO',
      oauthClientId: 'manar-cloud-copilot-1',
      oauthScope: SCOPE,
      taskId: 'task-1',
    },
    ...overrides,
  };
}

const chatGptAgent = (oauthClientId: string | null) =>
  cloudAgent({
    cloudBinding: {
      platform: 'CHATGPT',
      oauthClientId,
      oauthScope: SCOPE,
      taskId: 'task-1',
    },
  });

function setup(
  options: {
    agent?: Agent | null;
    env?: Record<string, unknown>;
    blocked?: (key: string) => boolean;
    proposal?: 'pending' | 'refused';
    auditHits?: number;
    paused?: boolean;
    /** The confirmed self-registered client is free of protocol mappers (default true). */
    clientClean?: boolean;
    /** Roles the person holds in the workspace right now; `null` = no ACTIVE membership. */
    membershipRoles?: string[] | null;
    /** Tenant rows by slug (shared realm). */
    tenants?: Record<
      string,
      { id: string; status: string; keycloakIssuerUrl: string | null }
    >;
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
  const resolveByIssuer = vi.fn((iss: string) =>
    Promise.resolve(issuers[iss] ? { ...issuers[iss], issuerUrl: iss } : null),
  );
  const knownIssuers = { resolveByIssuer } as unknown as KnownIssuerRegistry;
  const getJwks = vi.fn(() => jwks);
  const jwksCache = { getJwks } as unknown as JwksCacheService;
  const tenantClient = {
    agent: {
      findUnique: () =>
        Promise.resolve(
          options.agent === undefined ? cloudAgent() : options.agent,
        ),
    },
  };
  const getClient = vi.fn().mockResolvedValue(tenantClient);
  const tenants = { getClient } as unknown as TenantDatabaseManager;
  const recordSafely = vi.fn().mockResolvedValue(undefined);
  const audit = { recordSafely } as unknown as AuditService;
  const proposeDcrClient = vi
    .fn()
    .mockResolvedValue(options.proposal ?? 'pending');
  const isPaused = vi.fn().mockResolvedValue(options.paused ?? false);
  const confirmedClientIsClean = vi
    .fn()
    .mockResolvedValue(options.clientClean ?? true);
  const cloudAgents = {
    proposeDcrClient,
    confirmedClientIsClean,
    isPaused,
  } as unknown as CloudAgentsService;
  const resolveActive = vi.fn(() =>
    options.membershipRoles === null
      ? Promise.reject(new ForbiddenException('Workspace not available'))
      : Promise.resolve({
          roles: options.membershipRoles ?? ['TENANT_OWNER'],
        }),
  );
  const membership = { resolveActive } as unknown as MembershipService;
  const control = {
    tenant: {
      findUnique: ({ where }: { where: { slug: string } }) =>
        Promise.resolve(options.tenants?.[where.slug] ?? null),
    },
  } as unknown as ControlPrismaService;
  const increment = vi.fn((key: string) => {
    const blocked = options.blocked?.(key) ?? false;
    return Promise.resolve({
      totalHits: key.startsWith('cloud-mcp-audit:')
        ? (options.auditHits ?? 1)
        : 1,
      timeToExpire: 60,
      isBlocked: blocked,
      timeToBlockExpire: blocked ? 30 : 0,
    });
  });
  const limits = { increment } as unknown as ThrottlerStorage;
  const guard = new CloudMcpAuthGuard(
    config,
    knownIssuers,
    jwksCache,
    tenants,
    audit,
    cloudAgents,
    limits,
    membership,
    control,
  );
  return {
    guard,
    config,
    recordSafely,
    increment,
    getClient,
    proposeDcrClient,
    resolveByIssuer,
    getJwks,
    resolveActive,
    isPaused,
  };
}

function context(
  authorization?: string,
  params: Record<string, string> = {
    tenantSlug: 'acme',
    agentSlug: 'copilot-1',
  },
  ip = '203.0.113.7',
) {
  const request = {
    params,
    ip,
    headers: authorization ? { authorization } : {},
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

async function rejections(reason: string): Promise<number> {
  const metric = await registry
    .getSingleMetric('manar_cloud_mcp_token_rejections_total')
    ?.get();
  return metric?.values.find((v) => v.labels.reason === reason)?.value ?? 0;
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
      'another tenant issuer on this tenant path',
      () => token({}, { issuer: OTHER_ISSUER }),
      'issuer_tenant_mismatch',
    ],
    [
      'a key the realm never used',
      () => token({}, { key: strangerKey }),
      'invalid_token',
    ],
    ['garbage', () => Promise.resolve('not-a-jwt'), 'malformed_token'],
  ])(
    '401 for %s before the signature verified: a metric, no tenant database, no audit',
    async (_label, make, reason) => {
      const before = await rejections(reason);
      const { ctx, replyHeaders } = context(`Bearer ${await make()}`);
      const { status, body } = await refusal(s.guard.canActivate(ctx));
      expect([status, body.reason]).toEqual([401, reason]);
      expect(replyHeaders['WWW-Authenticate']).toContain(
        'error="invalid_token"',
      );
      expect(s.recordSafely).not.toHaveBeenCalled();
      expect(s.getClient).not.toHaveBeenCalled();
      expect(await rejections(reason)).toBe(before + 1);
    },
  );

  it.each([
    [
      'wrong audience',
      () => token({}, { aud: 'https://mcp.manar.test/mcp/acme/other' }),
      'wrong_audience',
    ],
    [
      'an audience naming another agent too',
      () =>
        token({}, { aud: [MCP_URL, 'https://mcp.manar.test/mcp/acme/other'] }),
      'foreign_audience',
    ],
    ['expired', () => token({}, { expiresIn: '-1s' }), 'token_expired'],
    ['an ID token', () => token({ typ: 'ID' }), 'not_an_access_token'],
  ])(
    '401 for %s after the signature verified: audited in the issuer tenant without the token',
    async (_label, make, reason) => {
      const raw = await make();
      const { ctx } = context(`Bearer ${raw}`);
      const { status, body } = await refusal(s.guard.canActivate(ctx));
      expect([status, body.reason]).toEqual([401, reason]);
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
    ['another client', { azp: 'some-other-client' }, 'unknown_client'],
    ['the scope missing', { scope: 'openid profile' }, 'unknown_client'],
    [
      'a person without the agent role',
      { manar_roles: ['TENANT_OWNER'] },
      'user_not_allowed',
    ],
    ['no role claim at all', { manar_roles: undefined }, 'user_not_allowed'],
  ])('403 for %s', async (_label, claims, reason) => {
    const { ctx, replyHeaders } = context(`Bearer ${await token(claims)}`);
    const { status, body } = await refusal(s.guard.canActivate(ctx));
    expect([status, body.reason]).toEqual([403, reason]);
    expect(replyHeaders['WWW-Authenticate']).toContain(
      'error="insufficient_scope"',
    );
    expect(s.recordSafely).toHaveBeenCalledTimes(1);
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

  describe('ChatGPT (self-registered client)', () => {
    it('the first eligible client waits for an admin: 403 cloud_client_pending_approval, nothing bound', async () => {
      const g = setup({ agent: chatGptAgent(null) });
      const call = context(`Bearer ${await token({ azp: 'dcr-client-1' })}`);
      const { status, body } = await refusal(g.guard.canActivate(call.ctx));
      expect([status, body.reason]).toEqual([
        403,
        'cloud_client_pending_approval',
      ]);
      expect(g.proposeDcrClient).toHaveBeenCalledWith(
        't-acme',
        'agent-1',
        'dcr-client-1',
      );
    });

    it('a confirmed client is accepted and no other is', async () => {
      const g = setup({ agent: chatGptAgent('dcr-client-1') });
      const ok = context(`Bearer ${await token({ azp: 'dcr-client-1' })}`);
      await expect(g.guard.canActivate(ok.ctx)).resolves.toBe(true);
      const other = context(`Bearer ${await token({ azp: 'dcr-client-2' })}`);
      expect((await refusal(g.guard.canActivate(other.ctx))).body.reason).toBe(
        'unknown_client',
      );
      expect(g.proposeDcrClient).not.toHaveBeenCalled();
    });

    it('an ineligible client is refused', async () => {
      const g = setup({ agent: chatGptAgent(null), proposal: 'refused' });
      const { ctx } = context(`Bearer ${await token({ azp: 'admin-cli' })}`);
      expect((await refusal(g.guard.canActivate(ctx))).body.reason).toBe(
        'unknown_client',
      );
    });

    it('never proposes another agent pre-registered client, or for a person without the role', async () => {
      const g = setup({ agent: chatGptAgent(null) });
      const precreated = context(
        `Bearer ${await token({ azp: 'manar-cloud-another-agent' })}`,
      );
      expect((await refusal(g.guard.canActivate(precreated.ctx))).status).toBe(
        403,
      );
      const noRole = context(
        `Bearer ${await token({ azp: 'dcr-client-1', manar_roles: [] })}`,
      );
      expect((await refusal(g.guard.canActivate(noRole.ctx))).status).toBe(403);
      expect(g.proposeDcrClient).not.toHaveBeenCalled();
    });
  });

  describe('budgets', () => {
    const keys = (g: ReturnType<typeof setup>) =>
      g.increment.mock.calls.map((c) => c[0]);

    it('an accepted call uses only the per-agent budget', async () => {
      const g = setup();
      await g.guard.canActivate(context(`Bearer ${await token()}`).ctx);
      expect(keys(g)).toEqual(['cloud-mcp:t-acme:agent-1']);
    });

    it('a refused call uses only the failure budgets, never the agent budget; the tenant budget only for parsed tokens', async () => {
      const g = setup();
      await refusal(g.guard.canActivate(context().ctx));
      await refusal(g.guard.canActivate(context('Bearer not-a-jwt').ctx));
      await refusal(
        g.guard.canActivate(
          context(
            `Bearer ${await token({}, { issuer: 'https://evil.test/realms/x' })}`,
          ).ctx,
        ),
      );
      expect(keys(g)).toEqual([
        'cloud-mcp-fail:acme:203.0.113.7',
        'cloud-mcp-fail:acme:203.0.113.7',
        'cloud-mcp-fail:acme:203.0.113.7',
        'cloud-mcp-fail-tenant:acme',
      ]);
    });

    it('429 with Retry-After over the per-agent limit', async () => {
      const g = setup({ blocked: (k) => k.startsWith('cloud-mcp:') });
      const call = context(`Bearer ${await token()}`);
      expect((await refusal(g.guard.canActivate(call.ctx))).status).toBe(429);
      expect(call.replyHeaders['Retry-After']).toBe('30');
    });

    it('a caller over its failure budget gets 429 before any key, database or Keycloak work', async () => {
      const g = setup({
        blocked: (k) => k === 'cloud-mcp-fail:acme:203.0.113.7',
      });
      const bad = context(
        `Bearer ${await token({}, { aud: 'https://mcp.manar.test/mcp/acme/other' })}`,
      );
      expect((await refusal(g.guard.canActivate(bad.ctx))).status).toBe(429);
      expect(g.recordSafely).not.toHaveBeenCalled();
      g.getJwks.mockClear();
      g.resolveByIssuer.mockClear();
      g.getClient.mockClear();
      const next = context(`Bearer ${await token()}`);
      expect((await refusal(g.guard.canActivate(next.ctx))).status).toBe(429);
      expect(next.replyHeaders['Retry-After']).toBeDefined();
      expect(g.getJwks).not.toHaveBeenCalled();
      expect(g.resolveByIssuer).not.toHaveBeenCalled();
      expect(g.getClient).not.toHaveBeenCalled();
      // Another caller is not affected.
      await expect(
        g.guard.canActivate(
          context(`Bearer ${await token()}`, undefined, '198.51.100.20').ctx,
        ),
      ).resolves.toBe(true);
    });

    it('with the tenant failure budget exhausted: tokenless discovery still gets 401, valid tokens pass, failing tokens get 429', async () => {
      const g = setup({ blocked: (k) => k === 'cloud-mcp-fail-tenant:acme' });
      const discovery = context(undefined, undefined, '198.51.100.30');
      expect((await refusal(g.guard.canActivate(discovery.ctx))).status).toBe(
        401,
      );
      expect(discovery.replyHeaders['WWW-Authenticate']).toContain(
        'resource_metadata=',
      );
      await expect(
        g.guard.canActivate(
          context(`Bearer ${await token()}`, undefined, '198.51.100.31').ctx,
        ),
      ).resolves.toBe(true);
      const failing = context(
        `Bearer ${await token({}, { expiresIn: '-1s' })}`,
        undefined,
        '198.51.100.32',
      );
      expect((await refusal(g.guard.canActivate(failing.ctx))).status).toBe(
        429,
      );
      expect(g.recordSafely).not.toHaveBeenCalled();
    });

    it('a validly signed refused token is audited once a minute per tenant, client and reason', async () => {
      const g = setup({ auditHits: 2 });
      const bad = context(
        `Bearer ${await token({}, { aud: 'https://mcp.manar.test/mcp/acme/other' })}`,
      );
      expect((await refusal(g.guard.canActivate(bad.ctx))).status).toBe(401);
      expect(g.recordSafely).not.toHaveBeenCalled();
      expect(keys(g)).toContain(
        'cloud-mcp-audit:t-acme:manar-cloud-copilot-1:wrong_audience',
      );
    });
  });

  it('404 when the endpoint is off or the path is not a slug pair', async () => {
    const off = setup({ env: { MANAR_MCP_ENABLED: 'false' } });
    expect((await refusal(off.guard.canActivate(context().ctx))).status).toBe(
      404,
    );
    const bad = context(undefined, { tenantSlug: 'ACME', agentSlug: 'x' });
    expect((await refusal(s.guard.canActivate(bad.ctx))).status).toBe(404);
  });
});

describe('CloudMcpController protected resource metadata', () => {
  const request = { ip: '203.0.113.7' } as never;
  const limits = (blocked = false) =>
    ({
      increment: () =>
        Promise.resolve({
          totalHits: 1,
          timeToExpire: 60,
          isBlocked: blocked,
          timeToBlockExpire: 0,
        }),
    }) as unknown as ThrottlerStorage;

  it('names the tenant realm as the authorization server and the agent scope; caches the tenant', async () => {
    const { config } = setup();
    const findUnique = vi
      .fn()
      .mockResolvedValue({ status: 'ACTIVE', keycloakIssuerUrl: ISSUER });
    const control = {
      tenant: { findUnique },
    } as unknown as ControlPrismaService;
    const controller = new CloudMcpController(
      config,
      control,
      {} as never,
      limits(),
    );
    const expected = {
      resource: MCP_URL,
      authorization_servers: [ISSUER],
      scopes_supported: [SCOPE],
      bearer_methods_supported: ['header'],
      resource_name: 'Manar governed tools',
    };
    await expect(
      controller.protectedResourceMetadata('acme', 'copilot-1', request),
    ).resolves.toEqual(expected);
    await expect(
      controller.protectedResourceMetadata('acme', 'copilot-1', request),
    ).resolves.toEqual(expected);
    expect(findUnique).toHaveBeenCalledTimes(1);

    const gone = new CloudMcpController(
      config,
      { tenant: { findUnique: () => Promise.resolve(null) } } as never,
      {} as never,
      limits(),
    );
    await expect(
      gone.protectedResourceMetadata('nope', 'x', request),
    ).rejects.toThrow();
  });

  it('429 over the per-address limit, before any database read', async () => {
    const { config } = setup();
    const findUnique = vi.fn();
    const controller = new CloudMcpController(
      config,
      { tenant: { findUnique } } as never,
      {} as never,
      limits(true),
    );
    const error = await controller
      .protectedResourceMetadata('acme', 'copilot-1', request)
      .catch((e: unknown) => e);
    expect((error as HttpException).getStatus()).toBe(429);
    expect(findUnique).not.toHaveBeenCalled();
  });
});

describe('legacy (own realm) agent over the plan cap', () => {
  it('is paused: 403 agent_paused, audited, nothing deleted', async () => {
    const s = setup({ paused: true });
    const { ctx } = context(`Bearer ${await token()}`);
    const { status, body } = await refusal(s.guard.canActivate(ctx));
    expect([status, body.reason]).toEqual([403, 'agent_paused']);
    expect(s.recordSafely).toHaveBeenCalledTimes(1);
  });
});

/**
 * The shared realm (spec 4.1, #38): one issuer for every tenant. The tenant is proven by the
 * `manar_tenant` claim, the person by Manar's Membership, the client by `azp`.
 */
describe('CloudMcpAuthGuard on the shared realm', () => {
  const SHARED = 'https://auth.manar.test/realms/manar';
  const T_SCOPE = 'manar-mcp-t-acme-copilot-1';
  const T_CLIENT = 'manar-cloud-t-acme-copilot-1';
  const TENANTS = {
    acme: { id: 't-acme', status: 'ACTIVE', keycloakIssuerUrl: null },
    globex: { id: 't-globex', status: 'ACTIVE', keycloakIssuerUrl: null },
    // Has its own realm: never served by the shared issuer.
    own: { id: 't-own', status: 'ACTIVE', keycloakIssuerUrl: ISSUER },
  };
  const sharedAgent = (
    overrides: Partial<Agent['cloudBinding'] & object> = {},
  ) =>
    cloudAgent({
      cloudBinding: {
        platform: 'COPILOT_STUDIO',
        oauthClientId: T_CLIENT,
        oauthScope: T_SCOPE,
        taskId: 'task-1',
        ...overrides,
      },
    });
  const shared = (o: Parameters<typeof setup>[0] = {}) =>
    setup({
      agent: sharedAgent(),
      tenants: TENANTS,
      ...o,
      env: { MANAR_MCP_SHARED_ISSUER: SHARED, ...o.env },
    });
  const sharedToken = (
    overrides: Record<string, unknown> = {},
    options: Parameters<typeof token>[1] = {},
  ) =>
    token(
      {
        azp: T_CLIENT,
        scope: `openid ${T_SCOPE}`,
        manar_tenant: 't-acme',
        manar_roles: undefined,
        ...overrides,
      },
      { issuer: SHARED, ...options },
    );

  it('accepts: tenant claim, audience, client and an ACTIVE membership all agree', async () => {
    const s = shared();
    const { ctx, request } = context(`Bearer ${await sharedToken()}`);
    await expect(s.guard.canActivate(ctx)).resolves.toBe(true);
    expect(request.cloudAgent?.context.tenant).toEqual({
      id: 't-acme',
      slug: 'acme',
    });
    expect(s.resolveActive).toHaveBeenCalledWith({
      issuer: 'https://auth.manar.test/realms/manar',
      subject: 'user-1',
      requestedTenantId: 't-acme',
    });
  });

  it('a bare 401 costs no tenant lookup and carries no scope hint (the metadata lists it)', async () => {
    const s = shared();
    const lookup = vi.spyOn(
      (s.guard as unknown as { control: ControlPrismaService }).control.tenant,
      'findUnique',
    );
    const { ctx, replyHeaders } = context(undefined, {
      tenantSlug: 'random-xyz',
      agentSlug: 'a',
    });
    await refusal(s.guard.canActivate(ctx));
    expect(lookup).not.toHaveBeenCalled();
    expect(replyHeaders['WWW-Authenticate']).not.toContain('scope=');
  });

  it('a token for another issuer or garbage does no tenant lookup either; a shared token does, and names the scope', async () => {
    const s = shared();
    const lookup = vi.spyOn(
      (s.guard as unknown as { control: ControlPrismaService }).control.tenant,
      'findUnique',
    );
    await refusal(s.guard.canActivate(context('Bearer not-a-jwt').ctx));
    await refusal(
      s.guard.canActivate(
        context(`Bearer ${await token({}, { issuer: 'https://evil.test/r' })}`)
          .ctx,
      ),
    );
    expect(lookup).not.toHaveBeenCalled();
    const { ctx, replyHeaders } = context(
      `Bearer ${await sharedToken({ manar_tenant: 't-globex' })}`,
    );
    await refusal(s.guard.canActivate(ctx));
    expect(lookup).toHaveBeenCalledTimes(1);
    expect(replyHeaders['WWW-Authenticate']).toContain(`scope="${T_SCOPE}"`);
  });

  it('unknown slugs are cached apart from real tenants and never evict them', async () => {
    const s = shared();
    const g = s.guard as unknown as {
      tenantBySlug(slug: string): Promise<unknown>;
      tenantsBySlug: Map<string, unknown>;
      unknownSlugs: Map<string, unknown>;
    };
    await g.tenantBySlug('acme');
    for (let i = 0; i < 1_100; i++) await g.tenantBySlug(`nobody-${i}`);
    expect(g.tenantsBySlug.has('acme')).toBe(true);
    expect(g.unknownSlugs.size).toBeLessThanOrEqual(1_000);
  });

  it('a confirmed ChatGPT client that gained a protocol mapper is refused', async () => {
    const chat = { platform: 'CHATGPT', oauthClientId: T_CLIENT };
    const dirty = shared({
      agent: sharedAgent(chat),
      env: { MANAR_MCP_CHATGPT_ENABLED: 'true' },
      clientClean: false,
    });
    const refused = await refusal(
      dirty.guard.canActivate(context(`Bearer ${await sharedToken()}`).ctx),
    );
    expect([refused.status, refused.body.reason]).toEqual([
      403,
      'unknown_client',
    ]);
  });

  it('an existing ChatGPT binding is refused when ChatGPT is switched off on the shared realm', async () => {
    const chat = { platform: 'CHATGPT', oauthClientId: T_CLIENT };
    const off = shared({
      agent: sharedAgent(chat),
      env: { MANAR_MCP_CHATGPT_ENABLED: 'false' },
    });
    const refused = await refusal(
      off.guard.canActivate(context(`Bearer ${await sharedToken()}`).ctx),
    );
    expect([refused.status, refused.body.reason]).toEqual([
      403,
      'chatgpt_not_enabled',
    ]);
    const on = shared({ agent: sharedAgent(chat) });
    await expect(
      on.guard.canActivate(context(`Bearer ${await sharedToken()}`).ctx),
    ).resolves.toBe(true);
  });

  it("a token for tenant B used on tenant A's MCP URL is 401, and nothing lands in A's audit", async () => {
    const s = shared();
    const other = await sharedToken(
      {
        manar_tenant: 't-globex',
        scope: 'openid manar-mcp-t-globex-copilot-1',
      },
      { aud: 'https://mcp.manar.test/mcp/globex/copilot-1' },
    );
    const { ctx } = context(`Bearer ${other}`);
    const { status, body } = await refusal(s.guard.canActivate(ctx));
    expect([status, body.reason]).toEqual([401, 'wrong_audience']);
    expect(s.recordSafely).not.toHaveBeenCalled();
    expect(s.getClient).not.toHaveBeenCalled();
  });

  it.each([
    ['another tenant', { manar_tenant: 't-globex' }],
    ['no tenant claim', { manar_tenant: undefined }],
    ['a non-string tenant claim', { manar_tenant: ['t-acme'] }],
  ])(
    'right audience but %s in the tenant claim: 401 tenant_mismatch, no tenant database',
    async (_l, claims) => {
      const s = shared();
      const { ctx } = context(`Bearer ${await sharedToken(claims)}`);
      const { status, body } = await refusal(s.guard.canActivate(ctx));
      expect([status, body.reason]).toEqual([401, 'tenant_mismatch']);
      expect(s.getClient).not.toHaveBeenCalled();
      expect(s.recordSafely).not.toHaveBeenCalled();
    },
  );

  it("valid tenant claim but the azp of another agent's client: 403 unknown_client", async () => {
    const s = shared();
    const { ctx } = context(
      `Bearer ${await sharedToken({ azp: 'manar-cloud-t-acme-other' })}`,
    );
    const { status, body } = await refusal(s.guard.canActivate(ctx));
    expect([status, body.reason]).toEqual([403, 'unknown_client']);
  });

  it("a binding whose scope is another tenant's is refused even if the token carries this tenant's scope", async () => {
    const s = shared({
      agent: sharedAgent({ oauthScope: 'manar-mcp-t-globex-copilot-1' }), // gitleaks:allow (scope name, not a key)
    });
    const { ctx } = context(`Bearer ${await sharedToken()}`);
    const { status, body } = await refusal(s.guard.canActivate(ctx));
    expect([status, body.reason]).toEqual([403, 'binding_tenant_mismatch']);
  });

  it('removing the membership revokes at once: no ACTIVE membership is 403 user_not_allowed', async () => {
    const s = shared({ membershipRoles: null });
    const { ctx } = context(`Bearer ${await sharedToken()}`);
    const { status, body } = await refusal(s.guard.canActivate(ctx));
    expect([status, body.reason]).toEqual([403, 'user_not_allowed']);
  });

  it('a member with only a read-only role is refused', async () => {
    const s = shared({ membershipRoles: ['READ_ONLY', 'AUDITOR'] });
    const { ctx } = context(`Bearer ${await sharedToken()}`);
    expect((await refusal(s.guard.canActivate(ctx))).body.reason).toBe(
      'user_not_allowed',
    );
  });

  it('ignores a manar_roles claim: roles come from the membership, not the token', async () => {
    const s = shared({ membershipRoles: null });
    const { ctx } = context(
      `Bearer ${await sharedToken({ manar_roles: ['manar-agent-copilot-1'] })}`,
    );
    expect((await refusal(s.guard.canActivate(ctx))).status).toBe(403);
  });

  it('a paused agent (over the cap after a downgrade) is 403 agent_paused', async () => {
    const s = shared({ paused: true });
    const { ctx } = context(`Bearer ${await sharedToken()}`);
    const { status, body } = await refusal(s.guard.canActivate(ctx));
    expect([status, body.reason]).toEqual([403, 'agent_paused']);
    expect(s.isPaused).toHaveBeenCalledWith(
      't-acme',
      expect.anything(),
      'agent-1',
    );
  });

  it('a self-registered client is never accepted before the tenant admin confirms it', async () => {
    const s = shared({
      agent: sharedAgent({ platform: 'CHATGPT', oauthClientId: null }),
      env: { MANAR_MCP_CHATGPT_ENABLED: 'true' },
    });
    const { ctx } = context(
      `Bearer ${await sharedToken({ azp: 'dcr-attacker' })}`,
    );
    const { status, body } = await refusal(s.guard.canActivate(ctx));
    expect([status, body.reason]).toEqual([
      403,
      'cloud_client_pending_approval',
    ]);
    // Proposed for this tenant's agent only, from a member's token.
    expect(s.proposeDcrClient).toHaveBeenCalledWith(
      't-acme',
      'agent-1',
      'dcr-attacker',
    );
  });

  it('a confirmed client of tenant A is not accepted for tenant B (azp binds to the binding)', async () => {
    const s = shared({
      agent: sharedAgent({
        platform: 'CHATGPT',
        oauthClientId: 'dcr-of-globex',
      }),
    });
    const { ctx } = context(
      `Bearer ${await sharedToken({ azp: 'dcr-of-acme' })}`,
    );
    expect((await refusal(s.guard.canActivate(ctx))).status).toBe(403);
  });

  it('a shared-realm token for a tenant that has its own realm is refused', async () => {
    const s = shared();
    const { ctx } = context(
      `Bearer ${await sharedToken({}, { aud: 'https://mcp.manar.test/mcp/own/copilot-1' })}`,
      { tenantSlug: 'own', agentSlug: 'copilot-1' },
    );
    expect((await refusal(s.guard.canActivate(ctx))).body.reason).toBe(
      'unknown_issuer',
    );
  });

  it('a suspended tenant is refused', async () => {
    const s = shared({
      tenants: {
        ...TENANTS,
        acme: { ...TENANTS.acme, status: 'SUSPENDED' },
      },
    });
    const { ctx } = context(`Bearer ${await sharedToken()}`);
    expect((await refusal(s.guard.canActivate(ctx))).body.reason).toBe(
      'unknown_issuer',
    );
  });

  it('without a configured shared issuer a shared-realm token is unknown', async () => {
    const s = setup({ agent: sharedAgent(), tenants: TENANTS });
    const { ctx } = context(`Bearer ${await sharedToken()}`);
    expect((await refusal(s.guard.canActivate(ctx))).body.reason).toBe(
      'unknown_issuer',
    );
  });
});
