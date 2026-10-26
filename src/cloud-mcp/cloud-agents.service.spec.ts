import { ConflictException } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import { describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../audit/audit.service';
import type { AuthContext } from '../auth/auth-context';
import type { AppConfig } from '../config/env.validation';
import type { ControlPrismaService } from '../database/control-prisma.service';
import type { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import type { KeycloakAdminClient } from '../keycloak/keycloak-admin.client';
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
      .mockResolvedValue(options.taken ? { id: 'x' } : undefined),
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
    deleteById: vi.fn().mockResolvedValue(undefined),
  };
  const tasks = {
    createTask: vi.fn().mockResolvedValue({ id: 'task-1' }),
    revokeTask: vi.fn().mockResolvedValue(undefined),
  };
  const config = {
    get: (key: string) =>
      ({ MANAR_MCP_ENABLED: 'true', MANAR_MCP_HOST: 'mcp.manar.test' })[key],
  } as unknown as ConfigService<AppConfig, true>;
  const service = new CloudAgentsService(
    config,
    {
      tenant: {
        findUnique: () =>
          Promise.resolve({
            keycloakRealm: 'acme',
            keycloakIssuerUrl: 'https://id/realms/acme',
          }),
      },
    } as unknown as ControlPrismaService,
    {
      getClient: () => Promise.resolve(tenantClient),
    } as unknown as TenantDatabaseManager,
    kc as unknown as KeycloakAdminClient,
    tasks as unknown as TasksService,
    {
      resolveTaskPack: () => Promise.resolve(null),
    } as unknown as CatalogService,
    { recordSafely: () => Promise.resolve() } as unknown as AuditService,
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
    expect(state().agent?.status).toBe('PENDING_ENROLLMENT');
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
