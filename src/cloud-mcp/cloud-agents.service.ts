import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { z } from 'zod';
import { buildAgentIdentifier } from '../agents/agent-identifier';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import type { AuthContext } from '../auth/auth-context';
import type { AppConfig } from '../config/env.validation';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import {
  ENTRA_IDP_ALIAS,
  KeycloakAdminClient,
} from '../keycloak/keycloak-admin.client';
import { CatalogService, catalogGate } from '../platform/catalog.service';
import { CreateTaskRequestSchema } from '../tasks/tasks.validation';
import { TasksService } from '../tasks/tasks.service';
import { PRE_REGISTERED_CLIENT_PREFIX } from './cloud-mcp-auth.guard';
import {
  cloudMcpMetadataUrl,
  cloudMcpResourceUrl,
  cloudMcpScope,
  cloudMcpSettings,
} from './cloud-mcp.config';

const SLUG = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
const HttpsUrl = z
  .string()
  .url()
  .max(2048)
  .refine(
    (u) => u.startsWith('https://') && !u.includes('*'),
    'https URL, no wildcard',
  );

// The refined schema cannot be omitted from directly; the refine is restated below.
const TaskInput = z
  .object(CreateTaskRequestSchema.shape)
  .omit({ assignedAgentId: true });

export const ConnectCloudAgentSchema = z.object({
  slug: z.string().min(1).max(50).regex(SLUG),
  displayName: z.string().min(1).max(200),
  platform: z.enum(['COPILOT_STUDIO', 'CHATGPT']),
  /** Copilot Studio only: its callback URL, when already known (also settable later). */
  redirectUris: z.array(HttpsUrl).max(10).default([]),
  /** The standing task: same fields as `POST /tasks`, assigned to the new agent. */
  task: TaskInput.refine((t) => t.expiresAt.getTime() > Date.now(), {
    message: 'expiresAt must be in the future',
    path: ['expiresAt'],
  }),
});
export const RedirectUrisSchema = z.object({
  redirectUris: z.array(HttpsUrl).min(1).max(10),
});
export const BindTaskSchema = z.object({ taskId: z.string().min(1).max(64) });
export const EntraIdpSchema = z.object({
  directoryId: z.string().uuid(),
  clientId: z.string().uuid(),
  clientSecret: z.string().min(1).max(512),
});

/**
 * Connecting cloud agents (docs/cloud-agents.md). An agent of kind CLOUD is
 * created ACTIVE (no certificate to enroll), with its standing task, a realm
 * client scope that puts its MCP URL in the token audience, and either a
 * pre-registered confidential client (Copilot Studio) or DCR opened to the
 * configured redirect hosts (ChatGPT). Keycloak and database steps are not
 * one transaction: a failure part way leaves the agent PENDING_ENROLLMENT
 * without a binding, which the MCP endpoint refuses; revoke it and connect
 * again with another slug.
 */
@Injectable()
export class CloudAgentsService {
  constructor(
    private readonly config: ConfigService<AppConfig, true>,
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly keycloak: KeycloakAdminClient,
    private readonly tasks: TasksService,
    private readonly catalog: CatalogService,
    private readonly audit: AuditService,
  ) {}

  async connect(
    auth: AuthContext,
    input: z.infer<typeof ConnectCloudAgentSchema>,
  ) {
    const host = this.mcpHost();
    const { realm, issuer } = await this.realmOf(auth.tenant.id);
    const tenantClient = await this.tenants.getClient(auth.tenant.id);
    if (await tenantClient.agent.findUnique({ where: { slug: input.slug } })) {
      throw new ConflictException(`An agent with slug "${input.slug}" exists`);
    }

    const agent = await tenantClient.agent.create({
      data: {
        slug: input.slug,
        identifier: buildAgentIdentifier(auth.tenant.slug, input.slug),
        displayName: input.displayName,
        createdBy: auth.user.id,
        kind: 'CLOUD',
      },
    });
    const packId = await catalogGate(() =>
      this.catalog.resolveTaskPack(auth.tenant.id, agent.id, input.task.packId),
    );
    const task = await this.tasks.createTask(tenantClient, auth.tenant.id, {
      ...input.task,
      description: input.task.description ?? null,
      requesterId: auth.user.id,
      assignedAgentId: agent.id,
      packId,
    });

    const mcpUrl = cloudMcpResourceUrl(host, auth.tenant.slug, input.slug);
    const scope = cloudMcpScope(input.slug);
    const scopeId = await this.keycloak.createAudienceClientScope(
      realm,
      scope,
      mcpUrl,
      input.platform === 'CHATGPT',
    );
    let clientId: string | null = null;
    let clientSecret: string | null = null;
    if (input.platform === 'COPILOT_STUDIO') {
      clientId = `${PRE_REGISTERED_CLIENT_PREFIX}${input.slug}`;
      clientSecret = await this.keycloak.createMcpClient(
        realm,
        clientId,
        scopeId,
        input.redirectUris,
      );
    } else {
      await this.keycloak.allowDcrRedirectHosts(
        realm,
        cloudMcpSettings(this.config).dcrTrustedHosts,
      );
    }

    await tenantClient.$transaction([
      tenantClient.cloudAgentBinding.create({
        data: {
          agentId: agent.id,
          platform: input.platform,
          oauthClientId: clientId,
          oauthScope: scope,
          taskId: task.id,
          createdBy: auth.user.id,
        },
      }),
      tenantClient.agent.update({
        where: { id: agent.id },
        data: { status: 'ACTIVE' },
      }),
    ]);
    await this.audit.recordSafely(tenantClient, auth.tenant.id, {
      eventType: AUDIT_EVENT_TYPES.CLOUD_AGENT_CONNECTED,
      actor: { type: 'human', id: auth.user.id },
      data: {
        agentId: agent.id,
        slug: agent.slug,
        platform: input.platform,
        oauthClientId: clientId,
        oauthScope: scope,
        taskId: task.id,
        mcpUrl,
      },
    });

    return {
      agent: {
        id: agent.id,
        slug: agent.slug,
        identifier: agent.identifier,
        kind: 'CLOUD',
      },
      taskId: task.id,
      platform: input.platform,
      mcpUrl,
      resourceMetadataUrl: cloudMcpMetadataUrl(
        host,
        auth.tenant.slug,
        input.slug,
      ),
      authorizationServer: issuer,
      authorizationUrl: `${issuer}/protocol/openid-connect/auth`,
      tokenUrl: `${issuer}/protocol/openid-connect/token`,
      refreshUrl: `${issuer}/protocol/openid-connect/token`,
      scopes: [scope],
      ...(clientId
        ? {
            clientId,
            // Shown once; Keycloak keeps it, Manar does not.
            clientSecret,
            redirectUris: input.redirectUris,
          }
        : {
            registrationUrl: `${issuer}/clients-registrations/openid-connect`,
            dcrRedirectHosts: cloudMcpSettings(this.config).dcrTrustedHosts,
          }),
    };
  }

  /** Copilot Studio shows its callback URL only after the connector exists. */
  async setRedirectUris(
    auth: AuthContext,
    agentId: string,
    redirectUris: string[],
  ) {
    const { realm } = await this.realmOf(auth.tenant.id);
    const { tenantClient, binding } = await this.bindingOf(auth, agentId);
    if (!binding.oauthClientId) {
      throw new BadRequestException(
        'A ChatGPT agent registers its own client (DCR)',
      );
    }
    await this.keycloak.setClientRedirectUris(
      realm,
      binding.oauthClientId,
      redirectUris,
    );
    await this.audited(auth, tenantClient, { agentId, redirectUris });
    return { agentId, redirectUris };
  }

  /** Renews the standing task: an ACTIVE task already assigned to this agent. */
  async bindTask(auth: AuthContext, agentId: string, taskId: string) {
    const { tenantClient } = await this.bindingOf(auth, agentId);
    const task = await tenantClient.task.findUnique({ where: { id: taskId } });
    if (!task || task.assignedAgentId !== agentId || task.status !== 'ACTIVE') {
      throw new BadRequestException(
        'taskId must be an ACTIVE task assigned to this agent',
      );
    }
    await tenantClient.cloudAgentBinding.update({
      where: { agentId },
      data: { taskId },
    });
    await this.audited(auth, tenantClient, { agentId, taskId });
    return { agentId, taskId };
  }

  /**
   * The tenant realm brokers the tenant's Entra ID directory (single tenant, OIDC). Returns the
   * redirect URI to register on the Entra app registration.
   */
  async configureEntra(
    auth: AuthContext,
    input: z.infer<typeof EntraIdpSchema>,
  ) {
    const { realm, issuer } = await this.realmOf(auth.tenant.id);
    await this.keycloak.upsertEntraIdentityProvider(realm, input);
    const tenantClient = await this.tenants.getClient(auth.tenant.id);
    await this.audit.recordSafely(tenantClient, auth.tenant.id, {
      eventType: AUDIT_EVENT_TYPES.IDENTITY_PROVIDER_CONFIGURED,
      actor: { type: 'human', id: auth.user.id },
      data: {
        alias: ENTRA_IDP_ALIAS,
        directoryId: input.directoryId,
        clientId: input.clientId,
      },
    });
    return {
      alias: ENTRA_IDP_ALIAS,
      redirectUri: `${issuer}/broker/${ENTRA_IDP_ALIAS}/endpoint`,
    };
  }

  private mcpHost(): string {
    const host = cloudMcpSettings(this.config).host;
    if (!host) {
      throw new BadRequestException({
        statusCode: 400,
        reason: 'cloud_mcp_not_enabled',
      });
    }
    return host;
  }

  private async realmOf(tenantId: string) {
    const tenant = await this.control.tenant.findUnique({
      where: { id: tenantId },
    });
    if (!tenant?.keycloakRealm || !tenant.keycloakIssuerUrl) {
      throw new ConflictException('This tenant has no Keycloak realm');
    }
    return { realm: tenant.keycloakRealm, issuer: tenant.keycloakIssuerUrl };
  }

  private async bindingOf(auth: AuthContext, agentId: string) {
    const tenantClient = await this.tenants.getClient(auth.tenant.id);
    const binding = await tenantClient.cloudAgentBinding.findUnique({
      where: { agentId },
    });
    if (!binding) throw new NotFoundException('No cloud agent with this id');
    return { tenantClient, binding };
  }

  private async audited(
    auth: AuthContext,
    tenantClient: Awaited<ReturnType<TenantDatabaseManager['getClient']>>,
    data: Record<string, unknown>,
  ) {
    await this.audit.recordSafely(tenantClient, auth.tenant.id, {
      eventType: AUDIT_EVENT_TYPES.CLOUD_AGENT_UPDATED,
      actor: { type: 'human', id: auth.user.id },
      data,
    });
  }
}
