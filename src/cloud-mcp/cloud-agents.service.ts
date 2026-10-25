import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { z } from 'zod';
import { buildAgentIdentifier } from '../agents/agent-identifier';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import type { AuditActor } from '../audit/audit-event-types';
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
import {
  PRE_REGISTERED_CLIENT_PREFIX,
  cloudMcpMetadataUrl,
  cloudMcpResourceUrl,
  cloudMcpRole,
  cloudMcpScope,
  cloudMcpSettings,
} from './cloud-mcp.config';

type TenantClient = Awaited<ReturnType<TenantDatabaseManager['getClient']>>;
type Platform = 'COPILOT_STUDIO' | 'CHATGPT';

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
  /** Entra group whose members get the agent role on sign-in (needs the Entra provider). */
  entraGroupId: z.string().uuid().optional(),
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
export const DisconnectSchema = z.object({
  reason: z.string().min(1).max(500),
});

/** Keycloak names of one cloud agent; all derived from its slug. */
function keycloakNames(slug: string, platform: Platform) {
  return {
    scope: cloudMcpScope(slug),
    role: cloudMcpRole(slug),
    mapper: cloudMcpRole(slug),
    clientId:
      platform === 'COPILOT_STUDIO'
        ? `${PRE_REGISTERED_CLIENT_PREFIX}${slug}`
        : null,
  };
}

/**
 * Connecting and disconnecting cloud agents (docs/cloud-agents.md).
 *
 * Per agent, in the tenant realm: a realm role (who may use it), a client
 * scope (audience = its MCP URL, plus the role claim) and either a
 * pre-registered confidential client (Copilot Studio) or an entry in the
 * anonymous DCR policies (ChatGPT; the client that first authenticates is
 * then recorded, `bindDcrClient`). Connecting is all or nothing: a failure
 * undoes the Keycloak objects and the task already made, and leaves the agent
 * row PENDING_ENROLLMENT without a binding; connecting again with the same
 * slug resumes it.
 */
@Injectable()
export class CloudAgentsService {
  private readonly logger = new Logger(CloudAgentsService.name);

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
    const names = keycloakNames(input.slug, input.platform);
    const kc = this.keycloak;

    const existing = await tenantClient.agent.findUnique({
      where: { slug: input.slug },
      include: { cloudBinding: true },
    });
    // A connection that failed part way is resumed under the same slug.
    const resume =
      existing?.kind === 'CLOUD' &&
      existing.status === 'PENDING_ENROLLMENT' &&
      !existing.cloudBinding;
    if (existing && !resume) {
      throw new ConflictException(`An agent with slug "${input.slug}" exists`);
    }
    if (!resume && (await this.keycloakNamesTaken(realm, names))) {
      throw new ConflictException(
        `The realm already has a client, client scope or role named for "${input.slug}"`,
      );
    }
    if (
      input.entraGroupId &&
      !(await kc.identityProviderExists(realm, ENTRA_IDP_ALIAS))
    ) {
      throw new ConflictException(
        'Configure the Entra identity provider before naming an Entra group',
      );
    }

    const agent =
      existing ??
      (await tenantClient.agent.create({
        data: {
          slug: input.slug,
          identifier: buildAgentIdentifier(auth.tenant.slug, input.slug),
          displayName: input.displayName,
          createdBy: auth.user.id,
          kind: 'CLOUD',
        },
      }));
    const packId = await catalogGate(() =>
      this.catalog.resolveTaskPack(auth.tenant.id, agent.id, input.task.packId),
    );

    const mcpUrl = cloudMcpResourceUrl(host, auth.tenant.slug, input.slug);
    const dcrHosts = cloudMcpSettings(this.config).dcrTrustedHosts;
    const undo: Array<() => Promise<unknown>> = [];
    let clientSecret: string | null = null;
    let taskId: string;
    try {
      if (resume) {
        await this.removeKeycloakObjects(realm, names, input.platform, null);
      }
      undo.push(() => kc.deleteRealmRole(realm, names.role));
      await kc.createRealmRole(realm, names.role);
      undo.push(() => kc.deleteClientScope(realm, names.scope));
      const scopeId = await kc.createAgentClientScope(
        realm,
        names.scope,
        mcpUrl,
        names.role,
      );
      if (names.clientId) {
        const clientId = names.clientId;
        undo.push(() => kc.deleteClient(realm, clientId));
        clientSecret = await kc.createMcpClient(
          realm,
          clientId,
          scopeId,
          input.redirectUris,
        );
      } else {
        undo.push(() =>
          kc.updateDcrPolicy(realm, dcrHosts, (scopes) =>
            scopes.filter((s) => s !== names.scope),
          ),
        );
        await kc.updateDcrPolicy(realm, dcrHosts, (scopes) => [
          ...new Set([...scopes, names.scope]),
        ]);
      }
      if (input.entraGroupId) {
        undo.push(() =>
          kc.deleteIdpMapper(realm, ENTRA_IDP_ALIAS, names.mapper),
        );
        await kc.addGroupRoleMapper(
          realm,
          ENTRA_IDP_ALIAS,
          names.mapper,
          input.entraGroupId,
          names.role,
        );
      }
      const task = await this.tasks.createTask(tenantClient, auth.tenant.id, {
        ...input.task,
        description: input.task.description ?? null,
        requesterId: auth.user.id,
        assignedAgentId: agent.id,
        packId,
      });
      taskId = task.id;
      undo.push(() =>
        this.tasks.revokeTask(
          tenantClient,
          auth.tenant.id,
          task.id,
          'cloud agent connection failed',
          auth.user.id,
        ),
      );
      await tenantClient.$transaction([
        tenantClient.cloudAgentBinding.create({
          data: {
            agentId: agent.id,
            platform: input.platform,
            oauthClientId: names.clientId,
            oauthScope: names.scope,
            taskId: task.id,
            createdBy: auth.user.id,
          },
        }),
        tenantClient.agent.update({
          where: { id: agent.id },
          data: { status: 'ACTIVE', displayName: input.displayName },
        }),
      ]);
    } catch (error) {
      for (const step of undo.reverse()) {
        await step().catch((e: unknown) =>
          this.logger.error(
            `Undo after a failed cloud agent connection (agent ${agent.id}) failed: ${e instanceof Error ? e.message : String(e)}`,
          ),
        );
      }
      throw error;
    }

    await this.record(
      auth,
      tenantClient,
      AUDIT_EVENT_TYPES.CLOUD_AGENT_CONNECTED,
      {
        agentId: agent.id,
        slug: agent.slug,
        platform: input.platform,
        oauthClientId: names.clientId,
        oauthScope: names.scope,
        role: names.role,
        entraGroupId: input.entraGroupId ?? null,
        taskId,
        mcpUrl,
      },
    );

    return {
      agent: {
        id: agent.id,
        slug: agent.slug,
        identifier: agent.identifier,
        kind: 'CLOUD',
      },
      taskId,
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
      scopes: [names.scope],
      /** People need this realm role (or the Entra group) to use the agent. */
      role: names.role,
      ...(names.clientId
        ? {
            clientId: names.clientId,
            // Shown once; Keycloak keeps it, Manar does not.
            clientSecret,
            redirectUris: input.redirectUris,
          }
        : {
            registrationUrl: `${issuer}/clients-registrations/openid-connect`,
            dcrRedirectHosts: dcrHosts,
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
    if (binding.platform !== 'COPILOT_STUDIO' || !binding.oauthClientId) {
      throw new BadRequestException(
        'A ChatGPT agent registers its own client (DCR)',
      );
    }
    await this.keycloak.updateClient(realm, binding.oauthClientId, {
      redirectUris,
    });
    await this.record(
      auth,
      tenantClient,
      AUDIT_EVENT_TYPES.CLOUD_AGENT_UPDATED,
      {
        agentId,
        redirectUris,
      },
    );
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
    await this.record(
      auth,
      tenantClient,
      AUDIT_EVENT_TYPES.CLOUD_AGENT_UPDATED,
      {
        agentId,
        taskId,
      },
    );
    return { agentId, taskId };
  }

  /**
   * ChatGPT: forget the recorded self-registered client (and delete it), so the next client
   * that authenticates is recorded instead (the connector was recreated in ChatGPT).
   */
  async resetDcrClient(auth: AuthContext, agentId: string) {
    const { realm } = await this.realmOf(auth.tenant.id);
    const { tenantClient, binding } = await this.bindingOf(auth, agentId);
    if (binding.platform !== 'CHATGPT') {
      throw new BadRequestException(
        'Only a ChatGPT agent has a self-registered client',
      );
    }
    if (binding.oauthClientId) {
      await this.keycloak.deleteClient(realm, binding.oauthClientId);
    }
    await tenantClient.cloudAgentBinding.update({
      where: { agentId },
      data: { oauthClientId: null },
    });
    await this.record(
      auth,
      tenantClient,
      AUDIT_EVENT_TYPES.CLOUD_AGENT_UPDATED,
      {
        agentId,
        dcrClientReset: binding.oauthClientId,
      },
    );
    return { agentId, oauthClientId: null };
  }

  /**
   * Revokes a cloud agent and removes its realm objects (client, scope, role, Entra mapper, DCR
   * policy entry; DCR closes again when no ChatGPT agent is left). The agent is refused from the
   * first step; the clean-up can be repeated if Keycloak fails part way.
   */
  async disconnect(auth: AuthContext, agentId: string, reason: string) {
    const { realm } = await this.realmOf(auth.tenant.id);
    const { tenantClient, binding } = await this.bindingOf(auth, agentId);
    const agent = await tenantClient.agent.findUniqueOrThrow({
      where: { id: agentId },
    });
    if (agent.status !== 'REVOKED') {
      await tenantClient.agent.update({
        where: { id: agentId },
        data: { status: 'REVOKED' },
      });
      await this.tasks
        .revokeTask(
          tenantClient,
          auth.tenant.id,
          binding.taskId,
          reason,
          auth.user.id,
        )
        .catch(() => undefined); // already revoked or expired
      await this.record(
        auth,
        tenantClient,
        AUDIT_EVENT_TYPES.CLOUD_AGENT_DISCONNECTED,
        { agentId, slug: agent.slug, platform: binding.platform, reason },
      );
    }
    await this.removeKeycloakObjects(
      realm,
      keycloakNames(agent.slug, binding.platform),
      binding.platform,
      binding.platform === 'CHATGPT' ? binding.oauthClientId : null,
    );
    return { agentId, status: 'REVOKED' };
  }

  /**
   * The realm brokers the tenant's Entra ID directory (single tenant, OIDC), with the
   * create-only first login flow and untrusted emails. Returns the redirect URI to register on
   * the Entra app registration.
   */
  async configureEntra(
    auth: AuthContext,
    input: z.infer<typeof EntraIdpSchema>,
  ) {
    const { realm, issuer } = await this.realmOf(auth.tenant.id);
    const authority = `https://login.microsoftonline.com/${input.directoryId}`;
    await this.keycloak.upsertOidcIdentityProvider(realm, ENTRA_IDP_ALIAS, {
      displayName: 'Microsoft Entra ID',
      issuer: `${authority}/v2.0`,
      authorizationUrl: `${authority}/oauth2/v2.0/authorize`,
      tokenUrl: `${authority}/oauth2/v2.0/token`,
      jwksUrl: `${authority}/discovery/v2.0/keys`,
      logoutUrl: `${authority}/oauth2/v2.0/logout`,
      clientId: input.clientId,
      clientSecret: input.clientSecret,
    });
    const tenantClient = await this.tenants.getClient(auth.tenant.id);
    await this.record(
      auth,
      tenantClient,
      AUDIT_EVENT_TYPES.IDENTITY_PROVIDER_CONFIGURED,
      {
        alias: ENTRA_IDP_ALIAS,
        directoryId: input.directoryId,
        clientId: input.clientId,
      },
    );
    return {
      alias: ENTRA_IDP_ALIAS,
      redirectUri: `${issuer}/broker/${ENTRA_IDP_ALIAS}/endpoint`,
    };
  }

  /**
   * Called by the MCP guard for a ChatGPT agent with no client recorded yet, on a token that
   * passed every other check (signature, audience, scope, the person's agent role). Records
   * `clientId` when Keycloak shows it is a self-registered client whose redirect URIs are all on
   * the DCR trusted hosts, and turns off its password grant, implicit flow and service account
   * (a self-registered client may have asked for them). False: refuse the token.
   */
  async bindDcrClient(
    tenantId: string,
    agentId: string,
    clientId: string,
  ): Promise<boolean> {
    const { realm } = await this.realmOf(tenantId);
    const hosts = cloudMcpSettings(this.config).dcrTrustedHosts;
    const client = await this.keycloak.findClient(realm, clientId);
    const onTrustedHost = (uri: string) => {
      try {
        const url = new URL(uri);
        return url.protocol === 'https:' && hosts.includes(url.hostname);
      } catch {
        return false;
      }
    };
    if (
      !client ||
      client.enabled === false ||
      clientId === this.config.get('KEYCLOAK_CLIENT_ID', { infer: true }) ||
      clientId.startsWith(PRE_REGISTERED_CLIENT_PREFIX) ||
      !client.redirectUris?.length ||
      !client.redirectUris.every(onTrustedHost)
    ) {
      return false;
    }
    await this.keycloak.updateClient(realm, clientId, {
      directAccessGrantsEnabled: false,
      implicitFlowEnabled: false,
      serviceAccountsEnabled: false,
    });
    const tenantClient = await this.tenants.getClient(tenantId);
    let bound: boolean;
    try {
      const { count } = await tenantClient.cloudAgentBinding.updateMany({
        where: { agentId, oauthClientId: null },
        data: { oauthClientId: clientId },
      });
      bound =
        count === 1 ||
        (
          await tenantClient.cloudAgentBinding.findUnique({
            where: { agentId },
          })
        )?.oauthClientId === clientId;
    } catch {
      return false; // the client is already recorded for another agent (unique)
    }
    if (bound) {
      await this.audit.recordSafely(tenantClient, tenantId, {
        eventType: AUDIT_EVENT_TYPES.CLOUD_AGENT_UPDATED,
        actor: { type: 'system', id: 'system:cloud-mcp' },
        data: { agentId, dcrClientRecorded: clientId },
      });
    }
    return bound;
  }

  private async keycloakNamesTaken(
    realm: string,
    names: ReturnType<typeof keycloakNames>,
  ): Promise<boolean> {
    return (
      (names.clientId !== null &&
        (await this.keycloak.findClient(realm, names.clientId)) !==
          undefined) ||
      (await this.keycloak.findClientScopeId(realm, names.scope)) !==
        undefined ||
      (await this.keycloak.realmRoleExists(realm, names.role))
    );
  }

  private async removeKeycloakObjects(
    realm: string,
    names: ReturnType<typeof keycloakNames>,
    platform: Platform,
    dcrClientId: string | null,
  ): Promise<void> {
    const kc = this.keycloak;
    await kc.deleteIdpMapper(realm, ENTRA_IDP_ALIAS, names.mapper);
    if (names.clientId) await kc.deleteClient(realm, names.clientId);
    if (dcrClientId) await kc.deleteClient(realm, dcrClientId);
    if (platform === 'CHATGPT') {
      await kc.updateDcrPolicy(
        realm,
        cloudMcpSettings(this.config).dcrTrustedHosts,
        (scopes) => scopes.filter((s) => s !== names.scope),
      );
    }
    await kc.deleteClientScope(realm, names.scope);
    await kc.deleteRealmRole(realm, names.role);
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

  private async record(
    auth: AuthContext,
    tenantClient: TenantClient,
    eventType: (typeof AUDIT_EVENT_TYPES)[keyof typeof AUDIT_EVENT_TYPES],
    data: Record<string, unknown>,
  ) {
    const actor: AuditActor = { type: 'human', id: auth.user.id };
    await this.audit.recordSafely(tenantClient, auth.tenant.id, {
      eventType,
      actor,
      data,
    });
  }
}
