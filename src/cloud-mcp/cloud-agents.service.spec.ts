import { ConflictException } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import { describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../audit/audit.service';
import type { AuthContext } from '../auth/auth-context';
import type { AppConfig } from '../config/env.validation';
import type { ControlPrismaService } from '../database/control-prisma.service';
import type { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import type { KeycloakAdminClient } from '../keycloak/keycloak-admin.client';
import { PlanLimitError } from '../billing/plan-limit.error';
import type { EntitlementsService } from '../billing/entitlements.service';
import type { CatalogService } from '../platform/catalog.service';
import type { TasksService } from '../tasks/tasks.service';
import {
  CloudAgentsService,
  ConnectCloudAgentSchema,
} from './cloud-agents.service';

/** Connecting is all or nothing, and a failed connection resumes under the same slug. */

const AUTH = {
  tenant: { id: 't-acme', slug: 'acme' },
  user: { id: 'user-1' },
} as unknown as AuthContext;

function setup(
  options: {
    failClientOnce?: boolean;
    taken?: boolean;
    roleConflict?: boolean;
    /** The tenant has no realm of its own: it is on the shared realm. */
    shared?: boolean;
    env?: Record<string, unknown>;
    /** Cap check: rejects like `EntitlementsService.withinLimit` over the cap. */
    overCap?: boolean;
    entitlement?: { status: string; cloudAgents: number | null };
    catalogFails?: boolean;
    foundClient?: Record<string, unknown>;
    binding?: Record<string, unknown>;
  } = {},
) {
  let agent: Record<string, unknown> | null = null;
  let binding: Record<string, unknown> | null = null;
  const tenantClient = {
    agent: {
      findUnique: () =>
        Promise.resolve(agent ? { ...agent, cloudBinding: binding } : null),
      create: ({ data }: { data: Record<string, unknown> }) => {
        agent = { id: 'agent-1', status: 'PENDING_ENROLLMENT', ...data };
        return Promise.resolve(agent);
      },
      update: ({ data }: { data: Record<string, unknown> }) => {
        agent = { ...agent, ...data };
        return Promise.resolve(agent);
      },
    },
    cloudAgentBinding: {
      findUnique: () => Promise.resolve(options.binding ?? null),
      updateMany: vi.fn().mockResolvedValue({ count: 1 }),
      create: ({ data }: { data: Record<string, unknown> }) => {
        binding = data;
        return Promise.resolve(data);
      },
    },
    $transaction: (ops: Promise<unknown>[]) => Promise.all(ops),
  };
  let clientFailures = options.failClientOnce ? 1 : 0;
  const kc = {
    findClient: vi
      .fn()
      .mockResolvedValue(
        options.foundClient ?? (options.taken ? { id: 'x' } : undefined),
      ),
    findClientScopeId: vi.fn().mockResolvedValue(undefined),
    realmRoleExists: vi.fn().mockResolvedValue(false),
    identityProviderExists: vi.fn().mockResolvedValue(true),
    createRealmRole: vi.fn(() =>
      options.roleConflict
        ? Promise.reject(
            new Error('Keycloak Admin API POST failed with HTTP 409'),
          )
        : Promise.resolve(),
    ),
    realmRoleId: vi.fn().mockResolvedValue('role-id'),
    createAgentClientScope: vi.fn().mockResolvedValue('scope-id'),
    createMcpClient: vi.fn(() =>
      clientFailures-- > 0
        ? Promise.reject(new Error('Keycloak down'))
        : Promise.resolve({ uuid: 'client-uuid', secret: 'secret' }),
    ),
    updateDcrPolicy: vi.fn().mockResolvedValue([]),
    updateClient: vi.fn().mockResolvedValue(undefined),
    regenerateRegistrationAccessToken: vi.fn().mockResolvedValue(undefined),
    deleteById: vi.fn().mockResolvedValue(undefined),
  };
  const tasks = {
    createTask: vi.fn().mockResolvedValue({ id: 'task-1' }),
    revokeTask: vi.fn().mockResolvedValue(undefined),
  };
  const config = {
    get: (key: string) =>
      ({
        MANAR_MCP_ENABLED: 'true',
        MANAR_MCP_HOST: 'mcp.manar.test',
        ...options.env,
      })[key],
  } as unknown as ConfigService<AppConfig, true>;
  const service = new CloudAgentsService(
    config,
    {
      $transaction: (fn: (tx: unknown) => Promise<unknown>) =>
        fn({ $queryRaw: () => Promise.resolve([]) }),
      tenant: {
        findUnique: () =>
          Promise.resolve(
            options.shared
              ? { keycloakRealm: null, keycloakIssuerUrl: null }
              : {
                  keycloakRealm: 'acme',
                  keycloakIssuerUrl: 'https://id/realms/acme',
                },
          ),
      },
    } as unknown as ControlPrismaService,
    {
      getClient: () => Promise.resolve(tenantClient),
    } as unknown as TenantDatabaseManager,
    kc as unknown as KeycloakAdminClient,
    tasks as unknown as TasksService,
    {
      resolveTaskPack: () =>
        options.catalogFails
          ? Promise.reject(new Error('catalog down'))
          : Promise.resolve(null),
    } as unknown as CatalogService,
    { recordSafely: () => Promise.resolve() } as unknown as AuditService,
    {
      get: () =>
        Promise.resolve({
          status: options.entitlement?.status ?? 'active',
          limits: { cloudAgents: options.entitlement?.cloudAgents ?? null },
        }),
      withinLimit: (
        _tenant: string,
        _limit: string,
        _client: unknown,
        _count: unknown,
        create: (tx: unknown) => Promise<unknown>,
      ) =>
        options.overCap
          ? Promise.reject(
              new PlanLimitError('cloudAgents', 1, 1, 'https://up/grade'),
            )
          : create(tenantClient),
    } as unknown as EntitlementsService,
  );
  return { service, kc, tasks, state: () => ({ agent, binding }) };
}

const input = ConnectCloudAgentSchema.parse({
  slug: 'copilot-1',
  displayName: 'Copilot',
  platform: 'COPILOT_STUDIO',
  task: {
    name: 'standing',
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  },
});

describe('CloudAgentsService.connect', () => {
  it('undoes what it made in Keycloak when a step fails, and resumes under the same slug', async () => {
    const { service, kc, state } = setup({ failClientOnce: true });
    await expect(service.connect(AUTH, input)).rejects.toThrow('Keycloak down');
    // The client was never created: nothing of it is deleted. What was created goes, by id.
    expect(kc.deleteById.mock.calls).toEqual([
      ['acme', 'client-scopes/scope-id'],
      ['acme', 'roles-by-id/role-id'],
    ]);
    // The failed row is revoked, which frees the plan slot.
    expect(state().agent?.status).toBe('REVOKED');
    expect(state().binding).toBeNull();

    const result = await service.connect(AUTH, input);
    expect(result).toMatchObject({
      clientId: 'manar-cloud-copilot-1',
      clientSecret: 'secret',
      role: 'manar-agent-copilot-1',
    });
    expect(state().agent?.status).toBe('ACTIVE');
    expect(state().binding).toMatchObject({
      oauthScope: 'manar-mcp-copilot-1',
      keycloakIds: {
        roleId: 'role-id',
        scopeId: 'scope-id',
        clientUuid: 'client-uuid',
      },
    });
  });

  it("a conflict on create is never cleaned up: the object is someone else's", async () => {
    const { service, kc } = setup({ roleConflict: true });
    await expect(service.connect(AUTH, input)).rejects.toThrow('HTTP 409');
    expect(kc.deleteById).not.toHaveBeenCalled();
  });

  it('refuses before creating anything when the realm already has the client name', async () => {
    const { service, kc, state } = setup({ taken: true });
    await expect(service.connect(AUTH, input)).rejects.toBeInstanceOf(
      ConflictException,
    );
    expect(state().agent).toBeNull();
    expect(kc.createRealmRole).not.toHaveBeenCalled();
  });

  it('refuses a slug held by a connected agent', async () => {
    const { service } = setup();
    await service.connect(AUTH, input);
    await expect(service.connect(AUTH, input)).rejects.toBeInstanceOf(
      ConflictException,
    );
  });
});

describe('CloudAgentsService on the shared realm', () => {
  const SHARED = {
    MANAR_MCP_SHARED_ISSUER: 'https://auth.manar.test/realms/manar',
  };

  it('prefixes the scope and client with the tenant id, stamps the tenant, and makes no realm role', async () => {
    const { service, kc, state } = setup({ shared: true, env: SHARED });
    const result = await service.connect(AUTH, input);
    expect(kc.createRealmRole).not.toHaveBeenCalled();
    expect(kc.createAgentClientScope).toHaveBeenCalledWith(
      'manar',
      'manar-mcp-t-acme-copilot-1',
      'https://mcp.manar.test/mcp/acme/copilot-1',
      null,
      't-acme',
    );
    expect(kc.createMcpClient).toHaveBeenCalledWith(
      'manar',
      'manar-cloud-t-acme-copilot-1',
      'scope-id',
      [],
    );
    expect(result).toMatchObject({
      clientId: 'manar-cloud-t-acme-copilot-1',
      role: null,
      authorizationServer: 'https://auth.manar.test/realms/manar',
    });
    expect(state().binding).toMatchObject({
      oauthScope: 'manar-mcp-t-acme-copilot-1',
    });
  });

  it('refuses without a configured shared issuer (fail closed)', async () => {
    const { service, kc } = setup({ shared: true });
    await expect(service.connect(AUTH, input)).rejects.toBeInstanceOf(
      ConflictException,
    );
    expect(kc.createAgentClientScope).not.toHaveBeenCalled();
  });

  it('keeps ChatGPT off unless MANAR_MCP_CHATGPT_ENABLED is true, and Entra groups never apply', async () => {
    const off = setup({ shared: true, env: SHARED });
    await expect(
      off.service.connect(AUTH, { ...input, platform: 'CHATGPT' }),
    ).rejects.toMatchObject({ response: { reason: 'chatgpt_not_enabled' } });
    await expect(
      off.service.connect(AUTH, {
        ...input,
        entraGroupId: '6f1c5f0e-1111-4222-8333-944455556666',
      }),
    ).rejects.toThrow(/shared realm/);
    expect(off.kc.updateDcrPolicy).not.toHaveBeenCalled();
    const on = setup({
      shared: true,
      env: { ...SHARED, MANAR_MCP_CHATGPT_ENABLED: 'true' },
    });
    await expect(
      on.service.connect(AUTH, { ...input, platform: 'CHATGPT' }),
    ).resolves.toHaveProperty('registrationUrl');
  });

  it('never configures identity providers on the shared realm', async () => {
    const { service } = setup({ shared: true, env: SHARED });
    await expect(
      service.configureEntra(AUTH, {
        directoryId: '6f1c5f0e-1111-4222-8333-944455556666',
        clientId: '6f1c5f0e-1111-4222-8333-944455556667',
        clientSecret: 'x',
      }),
    ).rejects.toThrow(/shared realm/);
  });
});

describe('CloudAgentsService plan cap', () => {
  it('over the cap creates nothing: no agent row, nothing in Keycloak', async () => {
    const { service, kc, state } = setup({ overCap: true });
    await expect(service.connect(AUTH, input)).rejects.toBeInstanceOf(
      PlanLimitError,
    );
    expect(state().agent).toBeNull();
    expect(kc.createRealmRole).not.toHaveBeenCalled();
  });
});

describe('CloudAgentsService.proposeDcrClient on the shared realm', () => {
  const SCOPE = 'manar-mcp-t-acme-chat';
  const now = Date.now();
  const binding = {
    platform: 'CHATGPT',
    oauthClientId: null,
    pendingClientId: null,
    oauthScope: SCOPE,
    createdAt: new Date(now - 60_000),
  };
  const client = (scopes: string[]) => ({
    id: 'uuid-1',
    clientId: 'dcr-1',
    enabled: true,
    publicClient: false,
    redirectUris: ['https://chatgpt.com/connector/oauth/abc'],
    defaultClientScopes: [],
    optionalClientScopes: scopes,
    attributes: { 'client.secret.creation.time': String(now / 1000) },
  });
  const env = {
    MANAR_MCP_SHARED_ISSUER: 'https://auth.manar.test/realms/manar',
    MANAR_MCP_CHATGPT_ENABLED: 'true',
    KEYCLOAK_CLIENT_ID: 'manar-api',
  };

  it('proposes a client that carries exactly this agent scope', async () => {
    const { service } = setup({
      shared: true,
      env,
      binding,
      foundClient: client([SCOPE]),
    });
    await expect(
      service.proposeDcrClient('t-acme', 'agent-1', 'dcr-1'),
    ).resolves.toBe('pending');
  });

  it('proposes a public client (ChatGPT registers with token_endpoint_auth_method none)', async () => {
    const { service } = setup({
      shared: true,
      env,
      binding,
      foundClient: { ...client([SCOPE]), publicClient: true, attributes: {} },
    });
    await expect(
      service.proposeDcrClient('t-acme', 'agent-1', 'dcr-1'),
    ).resolves.toBe('pending');
  });

  it('refuses a public client with no registration time on a per-tenant realm', async () => {
    const { service } = setup({
      env,
      binding,
      foundClient: { ...client([]), publicClient: true, attributes: {} },
    });
    await expect(
      service.proposeDcrClient('t-acme', 'agent-1', 'dcr-1'),
    ).resolves.toBe('refused');
  });

  it('refuses a client with a protocol mapper (it could map an attribute onto sub)', async () => {
    const { service } = setup({
      shared: true,
      env,
      binding,
      foundClient: {
        ...client([SCOPE]),
        protocolMappers: [{ name: 'sub-override' }],
      },
    });
    await expect(
      service.proposeDcrClient('t-acme', 'agent-1', 'dcr-1'),
    ).resolves.toBe('refused');
  });

  it("refuses a client that also carries another tenant's agent scope", async () => {
    const { service } = setup({
      shared: true,
      env,
      binding,
      foundClient: client([SCOPE, 'manar-mcp-t-globex-chat']),
    });
    await expect(
      service.proposeDcrClient('t-acme', 'agent-1', 'dcr-1'),
    ).resolves.toBe('refused');
  });

  it("refuses a client that does not carry this agent's scope", async () => {
    const { service } = setup({
      shared: true,
      env,
      binding,
      foundClient: client(['manar-mcp-t-globex-chat']),
    });
    await expect(
      service.proposeDcrClient('t-acme', 'agent-1', 'dcr-1'),
    ).resolves.toBe('refused');
  });
});

describe('failed connects and lapsed workspaces', () => {
  it('a failure before Keycloak (catalog) also revokes the row, so the slot is free', async () => {
    const { service, kc, state } = setup({ catalogFails: true });
    await expect(service.connect(AUTH, input)).rejects.toThrow();
    expect(state().agent?.status).toBe('REVOKED');
    expect(kc.createRealmRole).not.toHaveBeenCalled();
  });

  it('disconnect works for an agent that never got a binding', async () => {
    const { service, state } = setup({ catalogFails: true });
    await expect(service.connect(AUTH, input)).rejects.toThrow();
    // Re-open it half way (as a crash would leave it) and disconnect.
    await expect(
      service.disconnect(AUTH, 'agent-1', 'cleanup'),
    ).resolves.toEqual({ agentId: 'agent-1', status: 'REVOKED' });
    expect(state().agent?.status).toBe('REVOKED');
  });

  it('a read-only (lapsed) workspace runs no cloud agent even with an unlimited cap', async () => {
    const { service } = setup({
      entitlement: { status: 'read_only', cloudAgents: null },
    });
    await expect(
      service.isPaused('t-acme', {} as never, 'agent-1'),
    ).resolves.toBe(true);
  });

  it('an unlimited active workspace pauses nothing', async () => {
    const { service } = setup({
      entitlement: { status: 'active', cloudAgents: null },
    });
    await expect(
      service.isPaused('t-acme', {} as never, 'agent-1'),
    ).resolves.toBe(false);
  });
});

describe('confirmedClientIsClean', () => {
  const env = {
    MANAR_MCP_SHARED_ISSUER: 'https://auth.manar.test/realms/manar',
  };
  it('is false once the client carries a mapper, and when it is gone', async () => {
    const mapped = setup({
      shared: true,
      env,
      foundClient: { id: 'u', clientId: 'c', protocolMappers: [{ name: 'm' }] },
    });
    await expect(
      mapped.service.confirmedClientIsClean('t-acme', 'c'),
    ).resolves.toBe(false);
    const gone = setup({ shared: true, env });
    await expect(
      gone.service.confirmedClientIsClean('t-acme', 'c'),
    ).resolves.toBe(false);
    const clean = setup({
      shared: true,
      env,
      foundClient: { id: 'u', clientId: 'c' },
    });
    await expect(
      clean.service.confirmedClientIsClean('t-acme', 'c'),
    ).resolves.toBe(true);
  });
});
