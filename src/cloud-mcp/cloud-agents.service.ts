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
  KeycloakFlowTamperedError,
} from '../keycloak/keycloak-admin.client';
import type { KeycloakClientRepresentation } from '../keycloak/keycloak-admin.client';
import { recordCloudMcpPendingClient } from '../metrics/metrics';
import { Prisma } from '../generated/tenant-client/client';
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
export const ConfirmClientSchema = z.object({
  clientId: z.string().min(1).max(255),
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

/** Ids of the realm objects a connect created; disconnect deletes these and nothing else. */
interface KeycloakIds {
  roleId?: string;
  scopeId?: string;
  clientUuid?: string;
  mapperId?: string;
}

/** What Manar checked about a waiting self-registered client (shown to the confirming admin). */
interface PendingClient {
  clientId: string;
  registeredAt: string;
  redirectUris: string[];
  grants: {
    authorizationCode: boolean;
    password: boolean;
    implicit: boolean;
    serviceAccount: boolean;
  };
}

/** Milliseconds since epoch Keycloak recorded the client's secret, i.e. its registration. */
function registeredAt(client: KeycloakClientRepresentation): number {
  return Number(client.attributes?.['client.secret.creation.time']) * 1000;
}

/**
 * Connecting and disconnecting cloud agents (docs/cloud-agents.md).
 *
 * Per agent, in the tenant realm: a realm role (who may use it), a client
 * scope (audience = its MCP URL, plus the role claim) and either a
 * pre-registered confidential client (Copilot Studio) or an entry in the
 * anonymous DCR policies (ChatGPT; the first eligible self-registered client
 * waits until a tenant admin confirms it). Connecting is all or nothing:
 * every realm object is undone by the id it got, only once its creation
 * succeeded, and the agent row stays PENDING_ENROLLMENT without a binding;
 * connecting again with the same slug resumes it. Names already in the realm
 * are a conflict, never cleaned up.
 */
@Injectable()
export class CloudAgentsService {
  private readonly logger = new Logger(CloudAgentsService.name);
  // ponytail: per-replica, one minute: a refused self-registered client is not looked up in
  // Keycloak again on every call (tenant + agent + client).
  private readonly refusedClients = new Map<string, number>();

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
    if (await this.keycloakNamesTaken(realm, names)) {
      throw new ConflictException(
        `The realm already has a client, client scope or role named for "${input.slug}"; remove it in Keycloak or use another slug`,
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
    const ids: KeycloakIds = {};
    // Each undo is pushed only after its creation succeeded.
    const undo: Array<() => Promise<unknown>> = [];
    let clientSecret: string | null = null;
    let taskId: string;
    try {
      await kc.createRealmRole(realm, names.role);
      undo.push(async () =>
        kc.deleteById(
          realm,
          `roles-by-id/${ids.roleId ?? (await kc.realmRoleId(realm, names.role))}`,
        ),
      );
      ids.roleId = await kc.realmRoleId(realm, names.role);
      ids.scopeId = await kc.createAgentClientScope(
        realm,
        names.scope,
        mcpUrl,
        names.role,
      );
      undo.push(() => kc.deleteById(realm, `client-scopes/${ids.scopeId}`));
      if (names.clientId) {
        const created = await kc.createMcpClient(
          realm,
          names.clientId,
          ids.scopeId,
          input.redirectUris,
        );
        ids.clientUuid = created.uuid;
        clientSecret = created.secret;
        undo.push(() => kc.deleteById(realm, `clients/${ids.clientUuid}`));
      } else {
        await this.withRealmLock(realm, () =>
          kc.updateDcrPolicy(realm, dcrHosts, (scopes) => [
            ...new Set([...scopes, names.scope]),
          ]),
        );
        undo.push(() =>
          this.withRealmLock(realm, () =>
            kc.updateDcrPolicy(realm, dcrHosts, (scopes) =>
              scopes.filter((s) => s !== names.scope),
            ),
          ),
        );
      }
      if (input.entraGroupId) {
        ids.mapperId = await kc.addGroupRoleMapper(
          realm,
          ENTRA_IDP_ALIAS,
          names.mapper,
          input.entraGroupId,
          names.role,
        );
        undo.push(() =>
          kc.deleteById(
            realm,
            `identity-provider/instances/${ENTRA_IDP_ALIAS}/mappers/${ids.mapperId}`,
          ),
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
            keycloakIds: { ...ids },
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

  /** The binding as an admin sees it, including a self-registered client waiting for confirmation. */
  async describe(auth: AuthContext, agentId: string) {
    const { binding } = await this.bindingOf(auth, agentId);
    return {
      agentId,
      platform: binding.platform,
      taskId: binding.taskId,
      oauthClientId: binding.oauthClientId,
      pendingClient: binding.pendingClientId
        ? { ...(binding.pendingClient as object), since: binding.pendingSince }
        : null,
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
      { agentId, redirectUris },
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
      { agentId, taskId },
    );
    return { agentId, taskId };
  }

  /**
   * Called by the MCP guard for a ChatGPT agent with no confirmed client, on a token that passed
   * every other check (signature, audience, scope, the person's agent role). The first client
   * that Keycloak shows was registered after the agent was connected, with every redirect URI on
   * a DCR trusted host and the authorization code grant only (no password grant, implicit flow
   * or service account), becomes the agent's waiting client: audited, logged and counted for
   * alerting. Nothing is bound until a tenant admin confirms it.
   */
  async proposeDcrClient(
    tenantId: string,
    agentId: string,
    clientId: string,
  ): Promise<'pending' | 'refused'> {
    const tenantClient = await this.tenants.getClient(tenantId);
    const binding = await tenantClient.cloudAgentBinding.findUnique({
      where: { agentId },
    });
    if (!binding || binding.platform !== 'CHATGPT' || binding.oauthClientId) {
      return 'refused';
    }
    if (binding.pendingClientId) {
      return binding.pendingClientId === clientId ? 'pending' : 'refused';
    }
    const cacheKey = `${tenantId}:${agentId}:${clientId}`;
    if ((this.refusedClients.get(cacheKey) ?? 0) > Date.now()) return 'refused';
    const { realm } = await this.realmOf(tenantId);
    const client = await this.keycloak.findClient(realm, clientId);
    if (!client || !this.isEligibleDcrClient(client, binding.createdAt)) {
      if (this.refusedClients.size > 10_000) this.refusedClients.clear();
      this.refusedClients.set(cacheKey, Date.now() + 60_000);
      return 'refused';
    }
    const pending: PendingClient = {
      clientId,
      registeredAt: new Date(registeredAt(client)).toISOString(),
      redirectUris: client.redirectUris ?? [],
      grants: {
        authorizationCode: client.standardFlowEnabled !== false,
        password: client.directAccessGrantsEnabled === true,
        implicit: client.implicitFlowEnabled === true,
        serviceAccount: client.serviceAccountsEnabled === true,
      },
    };
    const { count } = await tenantClient.cloudAgentBinding.updateMany({
      where: { agentId, oauthClientId: null, pendingClientId: null },
      data: {
        pendingClientId: clientId,
        pendingClient: { ...pending },
        pendingSince: new Date(),
      },
    });
    if (count === 0) {
      const now = await tenantClient.cloudAgentBinding.findUnique({
        where: { agentId },
      });
      return now?.pendingClientId === clientId ? 'pending' : 'refused';
    }
    recordCloudMcpPendingClient();
    this.logger.warn(
      `Cloud agent ${agentId} (tenant ${tenantId}): self-registered client "${clientId}" is waiting for a tenant admin to confirm it`,
    );
    await this.audit.recordSafely(tenantClient, tenantId, {
      eventType: AUDIT_EVENT_TYPES.CLOUD_AGENT_CLIENT_PENDING,
      actor: { type: 'system', id: 'system:cloud-mcp' },
      data: { agentId, ...pending },
    });
    return 'pending';
  }

  /**
   * A tenant admin confirms the waiting client (by its id, so a swapped one is not confirmed).
   * Keycloak then requires PKCE S256 from it and it gets no full scope, password grant, implicit
   * flow or service account.
   */
  async confirmDcrClient(auth: AuthContext, agentId: string, clientId: string) {
    const { realm } = await this.realmOf(auth.tenant.id);
    const { tenantClient, binding } = await this.bindingOf(auth, agentId);
    if (binding.pendingClientId !== clientId) {
      throw new ConflictException(
        'That client is not the one waiting for this agent',
      );
    }
    await this.keycloak.updateClient(realm, clientId, {
      fullScopeAllowed: false,
      directAccessGrantsEnabled: false,
      implicitFlowEnabled: false,
      serviceAccountsEnabled: false,
      attributes: { 'pkce.code.challenge.method': 'S256' },
    });
    try {
      await tenantClient.cloudAgentBinding.update({
        where: { agentId },
        data: {
          oauthClientId: clientId,
          pendingClientId: null,
          pendingClient: Prisma.DbNull,
          pendingSince: null,
        },
      });
    } catch {
      throw new ConflictException('That client is bound to another agent');
    }
    await this.record(
      auth,
      tenantClient,
      AUDIT_EVENT_TYPES.CLOUD_AGENT_CLIENT_CONFIRMED,
      { agentId, clientId, pendingClient: binding.pendingClient },
    );
    return { agentId, oauthClientId: clientId };
  }

  /**
   * ChatGPT: rejects the waiting client or forgets the confirmed one, and deletes every
   * self-registered client that carries this agent's scope (so the connector must register again
   * and wait for confirmation).
   */
  async resetDcrClient(auth: AuthContext, agentId: string) {
    const { realm } = await this.realmOf(auth.tenant.id);
    const { tenantClient, binding } = await this.bindingOf(auth, agentId);
    if (binding.platform !== 'CHATGPT') {
      throw new BadRequestException(
        'Only a ChatGPT agent has a self-registered client',
      );
    }
    const deleted = await this.deleteSelfRegisteredClients(
      realm,
      binding.oauthScope,
      binding.createdAt,
    );
    await tenantClient.cloudAgentBinding.update({
      where: { agentId },
      data: {
        oauthClientId: null,
        pendingClientId: null,
        pendingClient: Prisma.DbNull,
        pendingSince: null,
      },
    });
    await this.record(
      auth,
      tenantClient,
      AUDIT_EVENT_TYPES.CLOUD_AGENT_CLIENT_REJECTED,
      {
        agentId,
        confirmed: binding.oauthClientId,
        pending: binding.pendingClientId,
        deleted,
      },
    );
    return { agentId, oauthClientId: null, deletedClients: deleted };
  }

  /**
   * Revokes a cloud agent and removes what its connect created, by id (client, scope, role,
   * Entra mapper), the self-registered clients carrying its scope, and its DCR policy entry (DCR
   * closes when no ChatGPT agent is left). Refused from the first step; repeatable.
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
    const ids = binding.keycloakIds as KeycloakIds;
    const kc = this.keycloak;
    if (ids.mapperId) {
      await kc.deleteById(
        realm,
        `identity-provider/instances/${ENTRA_IDP_ALIAS}/mappers/${ids.mapperId}`,
      );
    }
    if (ids.clientUuid) await kc.deleteById(realm, `clients/${ids.clientUuid}`);
    if (binding.platform === 'CHATGPT') {
      await this.deleteSelfRegisteredClients(
        realm,
        binding.oauthScope,
        binding.createdAt,
      );
      await this.withRealmLock(realm, () =>
        kc.updateDcrPolicy(
          realm,
          cloudMcpSettings(this.config).dcrTrustedHosts,
          (scopes) => scopes.filter((s) => s !== binding.oauthScope),
        ),
      );
    }
    if (ids.scopeId) await kc.deleteById(realm, `client-scopes/${ids.scopeId}`);
    if (ids.roleId) await kc.deleteById(realm, `roles-by-id/${ids.roleId}`);
    return { agentId, status: 'REVOKED' };
  }

  /**
   * The realm brokers the tenant's Entra ID directory (single tenant, OIDC), with the
   * create-only first login flow, untrusted emails and one account per email in the realm.
   * Returns the redirect URI to register on the Entra app registration.
   */
  async configureEntra(
    auth: AuthContext,
    input: z.infer<typeof EntraIdpSchema>,
  ) {
    const { realm, issuer } = await this.realmOf(auth.tenant.id);
    const authority = `https://login.microsoftonline.com/${input.directoryId}`;
    try {
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
    } catch (error) {
      if (error instanceof KeycloakFlowTamperedError) {
        throw new ConflictException(error.message);
      }
      throw error;
    }
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

  private isEligibleDcrClient(
    client: KeycloakClientRepresentation,
    connectedAt: Date,
  ): boolean {
    const hosts = cloudMcpSettings(this.config).dcrTrustedHosts;
    const onTrustedHost = (uri: string) => {
      try {
        const url = new URL(uri);
        return url.protocol === 'https:' && hosts.includes(url.hostname);
      } catch {
        return false;
      }
    };
    const at = registeredAt(client);
    return (
      client.enabled !== false &&
      client.publicClient !== true &&
      client.clientId !==
        this.config.get('KEYCLOAK_CLIENT_ID', { infer: true }) &&
      !client.clientId.startsWith(PRE_REGISTERED_CLIENT_PREFIX) &&
      // Keycloak keeps seconds; a client registered in the same second as the connect counts.
      Number.isFinite(at) &&
      at >= Math.floor(connectedAt.getTime() / 1000) * 1000 &&
      (client.redirectUris?.length ?? 0) > 0 &&
      client.redirectUris!.every(onTrustedHost) &&
      client.standardFlowEnabled !== false &&
      client.directAccessGrantsEnabled !== true &&
      client.implicitFlowEnabled !== true &&
      client.serviceAccountsEnabled !== true
    );
  }

  /** Self-registered clients registered after `since` that carry `scope`; returns their ids. */
  private async deleteSelfRegisteredClients(
    realm: string,
    scope: string,
    since: Date,
  ): Promise<string[]> {
    const consoleClient = this.config.get('KEYCLOAK_CLIENT_ID', {
      infer: true,
    });
    const sinceMs = Math.floor(since.getTime() / 1000) * 1000;
    const doomed = (await this.keycloak.listClients(realm)).filter(
      (c) =>
        [
          ...(c.defaultClientScopes ?? []),
          ...(c.optionalClientScopes ?? []),
        ].includes(scope) &&
        c.clientId !== consoleClient &&
        !c.clientId.startsWith(PRE_REGISTERED_CLIENT_PREFIX) &&
        registeredAt(c) >= sinceMs,
    );
    for (const client of doomed) {
      await this.keycloak.deleteById(realm, `clients/${client.id}`);
    }
    return doomed.map((c) => c.clientId);
  }

  /**
   * Serializes read-modify-write of a realm's DCR policies across API replicas: a Postgres
   * transaction-level advisory lock on the control database, held while `fn` runs.
   */
  private withRealmLock<T>(realm: string, fn: () => Promise<T>): Promise<T> {
    return this.control.$transaction(
      async (tx) => {
        await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(${`manar-dcr-policy:${realm}`}))::text`;
        return fn();
      },
      { maxWait: 30_000, timeout: 60_000 },
    );
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
