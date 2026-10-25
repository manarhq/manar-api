import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppConfig } from '../config/env.validation';
import { AGENT_ROLE_CLAIM } from '../cloud-mcp/cloud-mcp.config';

/** Alias of the Entra ID identity provider in a tenant realm (docs/cloud-agents.md). */
export const ENTRA_IDP_ALIAS = 'entra';
/** First broker login flow Manar creates: new users only, never linking by email. */
export const CREATE_ONLY_BROKER_FLOW = 'manar first broker login';

export interface KeycloakClientRepresentation {
  id: string;
  clientId: string;
  enabled?: boolean;
  publicClient?: boolean;
  redirectUris?: string[];
  directAccessGrantsEnabled?: boolean;
  implicitFlowEnabled?: boolean;
  serviceAccountsEnabled?: boolean;
  defaultClientScopes?: string[];
  optionalClientScopes?: string[];
  [key: string]: unknown;
}

function isNotFound(error: unknown): boolean {
  return (
    error instanceof Error && error.message.includes('failed with HTTP 404')
  );
}

/**
 * Minimal wrapper around Keycloak's Admin REST API
 * (https://www.keycloak.org/docs-api/latest/rest-api/index.html), covering
 * exactly what `TenantProvisioningService` needs: create a realm, seed
 * realm roles, and create a confidential client. Deliberately not a
 * general-purpose Keycloak SDK — this project's only Keycloak admin
 * consumer is tenant provisioning.
 *
 * Authenticates as the bootstrap master-realm admin (Section 11: an
 * infrastructure operator, not an application-level super admin — Manar's
 * own HTTP surface never exposes this credential or any cross-tenant
 * view). The admin access token is short-lived (Keycloak's default is 60s)
 * and intentionally never cached across calls — provisioning is a rare,
 * low-frequency operation, so re-authenticating per call is simpler and
 * safer than reasoning about a cached token's expiry.
 */
@Injectable()
export class KeycloakAdminClient {
  private readonly logger = new Logger(KeycloakAdminClient.name);
  private readonly baseUrl: string;

  constructor(private readonly configService: ConfigService<AppConfig, true>) {
    this.baseUrl = configService.get('KEYCLOAK_BASE_URL', { infer: true });
  }

  /** Full issuer URL Keycloak stamps into a realm's tokens' `iss` claim. */
  issuerUrlForRealm(realmName: string): string {
    return `${this.baseUrl}/realms/${realmName}`;
  }

  /** JWKS endpoint for a given realm's issuer URL. */
  jwksUrlForIssuer(issuerUrl: string): string {
    return `${issuerUrl}/protocol/openid-connect/certs`;
  }

  async createRealm(realmName: string): Promise<void> {
    await this.adminRequest('POST', '/admin/realms', {
      realm: realmName,
      enabled: true,
    });
  }

  async createRealmRole(realmName: string, roleName: string): Promise<void> {
    await this.adminRequest(
      'POST',
      `/admin/realms/${encodeURIComponent(realmName)}/roles`,
      { name: roleName },
    );
  }

  /**
   * Finds a realm user by exact username, or `undefined` if none exists
   * (Phase 13's `demo:seed` idempotency check — see
   * `src/cli/commands/demo-seed.command.ts`; this method has no other
   * caller, since `TenantProvisioningService` never needs to look up a
   * user by name).
   */
  async findUserByUsername(
    realmName: string,
    username: string,
  ): Promise<{ id: string } | undefined> {
    const response = await this.adminRequest(
      'GET',
      `/admin/realms/${encodeURIComponent(realmName)}/users?username=${encodeURIComponent(username)}&exact=true`,
    );
    const users = (response.body ?? []) as Array<{ id: string }>;
    return users[0];
  }

  /**
   * Creates a realm user with a permanent password and returns its
   * generated id. Sets `firstName`/`lastName` (see
   * `test/support/keycloak-test-helpers.ts`'s identical comment: recent
   * Keycloak versions otherwise reject a direct-grant token request with
   * "Account is not fully set up" for a user with no name at all).
   */
  async createUser(
    realmName: string,
    input: {
      username: string;
      email: string;
      password: string;
      firstName: string;
      lastName: string;
    },
  ): Promise<string> {
    const createResponse = await this.adminRequest(
      'POST',
      `/admin/realms/${encodeURIComponent(realmName)}/users`,
      {
        username: input.username,
        email: input.email,
        firstName: input.firstName,
        lastName: input.lastName,
        enabled: true,
        emailVerified: true,
        requiredActions: [],
      },
      { returnLocation: true },
    );
    const userId = createResponse.location?.split('/').pop();
    if (!userId) {
      throw new Error(
        `Keycloak did not return a user id for "${input.username}" in realm "${realmName}"`,
      );
    }

    await this.adminRequest(
      'PUT',
      `/admin/realms/${encodeURIComponent(realmName)}/users/${userId}/reset-password`,
      { type: 'password', value: input.password, temporary: false },
    );

    return userId;
  }

  /** Idempotent: assigning a role a user already holds is a harmless no-op against Keycloak's own API. */
  async assignRealmRole(
    realmName: string,
    userId: string,
    roleName: string,
  ): Promise<void> {
    const roleResponse = await this.adminRequest(
      'GET',
      `/admin/realms/${encodeURIComponent(realmName)}/roles/${encodeURIComponent(roleName)}`,
    );
    const role = roleResponse.body as { id: string; name: string };

    await this.adminRequest(
      'POST',
      `/admin/realms/${encodeURIComponent(realmName)}/users/${userId}/role-mappings/realm`,
      [{ id: role.id, name: role.name }],
    );
  }

  /**
   * Phase 14 — the revoke half of `assignRealmRole`, used by
   * `UsersService.revokeRole` (`DELETE /users/:id/role-bindings/:role`) so
   * a Manar-side revoke actually updates Keycloak, the role-assignment
   * source of truth `JwtAuthGuard.syncRoleBindings` reconciles against on
   * every request (see `docs/human-auth.md`'s "Role assignment" section) —
   * without this, a locally-deleted `RoleBinding` row would simply
   * reappear the next time the affected user authenticates, since the
   * token's `realm_access.roles` claim would still list it. Idempotent,
   * same reason as `assignRealmRole`: removing a role mapping a user
   * doesn't hold is a harmless no-op against Keycloak's own API.
   */
  async removeRealmRole(
    realmName: string,
    userId: string,
    roleName: string,
  ): Promise<void> {
    const roleResponse = await this.adminRequest(
      'GET',
      `/admin/realms/${encodeURIComponent(realmName)}/roles/${encodeURIComponent(roleName)}`,
    );
    const role = roleResponse.body as { id: string; name: string };

    await this.adminRequest(
      'DELETE',
      `/admin/realms/${encodeURIComponent(realmName)}/users/${userId}/role-mappings/realm`,
      [{ id: role.id, name: role.name }],
    );
  }

  /**
   * Creates a confidential client and returns its generated secret.
   * `directAccessGrantsEnabled: true` is set so this client also supports
   * the Resource Owner Password Credentials grant — used by this phase's
   * tests to obtain real, Keycloak-signed tokens for a realm test user
   * without fabricating a JWT. The full interactive login redirect flow
   * (`standardFlowEnabled`) is Phase 11, but enabling it here now avoids a
   * client-config migration later.
   *
   * `redirectUris`/`webOrigins` (Phase 14 security cleanup 2) seed the
   * client's Standard Flow callback allow-list at creation time — see
   * `MANAR_WEB_BASE_URL`'s doc comment (`keycloak.config.ts`) for why this
   * value is static/known up front rather than something only a login
   * attempt can discover. Both default to an empty list (unset) so this
   * method's existing callers/tests that don't pass them see identical
   * behavior to before.
   */
  async createConfidentialClient(
    realmName: string,
    clientId: string,
    options?: { redirectUris?: string[]; webOrigins?: string[] },
  ): Promise<string> {
    const createResponse = await this.adminRequest(
      'POST',
      `/admin/realms/${encodeURIComponent(realmName)}/clients`,
      {
        clientId,
        protocol: 'openid-connect',
        publicClient: false,
        standardFlowEnabled: true,
        directAccessGrantsEnabled: true,
        serviceAccountsEnabled: false,
        enabled: true,
        redirectUris: options?.redirectUris ?? [],
        webOrigins: options?.webOrigins ?? [],
      },
      { returnLocation: true },
    );

    const location = createResponse.location;
    if (!location) {
      throw new Error(
        `Keycloak did not return a Location header when creating client "${clientId}" in realm "${realmName}"`,
      );
    }
    const clientUuid = location.split('/').pop();

    const secretResponse = await this.adminRequest(
      'GET',
      `/admin/realms/${encodeURIComponent(realmName)}/clients/${clientUuid}/client-secret`,
    );
    const secret = (secretResponse.body as { value?: string } | undefined)
      ?.value;
    if (!secret) {
      throw new Error(
        `Keycloak did not return a client secret for client "${clientId}" in realm "${realmName}"`,
      );
    }
    return secret;
  }

  // ---- Cloud agents (docs/cloud-agents.md) ----

  /** A client by clientId, or undefined. */
  async findClient(
    realmName: string,
    clientId: string,
  ): Promise<KeycloakClientRepresentation | undefined> {
    const found = (
      await this.adminRequest(
        'GET',
        `/admin/realms/${encodeURIComponent(realmName)}/clients?clientId=${encodeURIComponent(clientId)}`,
      )
    ).body as KeycloakClientRepresentation[] | undefined;
    return found?.find((c) => c.clientId === clientId);
  }

  /** A client scope id by name, or undefined. */
  async findClientScopeId(
    realmName: string,
    name: string,
  ): Promise<string | undefined> {
    const scopes = (
      await this.adminRequest(
        'GET',
        `/admin/realms/${encodeURIComponent(realmName)}/client-scopes`,
      )
    ).body as Array<{ id: string; name: string }> | undefined;
    return scopes?.find((s) => s.name === name)?.id;
  }

  async realmRoleExists(realmName: string, roleName: string): Promise<boolean> {
    try {
      await this.adminRequest(
        'GET',
        `/admin/realms/${encodeURIComponent(realmName)}/roles/${encodeURIComponent(roleName)}`,
      );
      return true;
    } catch (error) {
      if (isNotFound(error)) return false;
      throw error;
    }
  }

  /**
   * One cloud agent's client scope: an audience mapper adds the agent's MCP URL to the access
   * token, and a realm role mapper writes the agent role into `AGENT_ROLE_CLAIM` when the person
   * holds it (the role is the scope's only scope mapping, so a client without full scope gets
   * just that role). Not a realm default or optional scope: only the clients Manar assigns it to
   * (the agent's own client, or a self-registered client the DCR policy lets ask for it) get it.
   */
  async createAgentClientScope(
    realmName: string,
    name: string,
    audience: string,
    roleName: string,
  ): Promise<string> {
    const realm = encodeURIComponent(realmName);
    const created = await this.adminRequest(
      'POST',
      `/admin/realms/${realm}/client-scopes`,
      {
        name,
        protocol: 'openid-connect',
        attributes: {
          'include.in.token.scope': 'true',
          'display.on.consent.screen': 'true',
        },
        protocolMappers: [
          {
            name: 'mcp-audience',
            protocol: 'openid-connect',
            protocolMapper: 'oidc-audience-mapper',
            config: {
              'included.custom.audience': audience,
              'access.token.claim': 'true',
              'id.token.claim': 'false',
              'introspection.token.claim': 'true',
            },
          },
          {
            name: 'agent-role',
            protocol: 'openid-connect',
            protocolMapper: 'oidc-usermodel-realm-role-mapper',
            config: {
              'claim.name': AGENT_ROLE_CLAIM,
              multivalued: 'true',
              'jsonType.label': 'String',
              'access.token.claim': 'true',
              'id.token.claim': 'false',
              'userinfo.token.claim': 'false',
              'introspection.token.claim': 'true',
            },
          },
        ],
      },
      { returnLocation: true },
    );
    const scopeId = created.location?.split('/').pop();
    if (!scopeId) {
      throw new Error(
        `Keycloak did not return an id for client scope "${name}"`,
      );
    }
    const role = (
      await this.adminRequest(
        'GET',
        `/admin/realms/${realm}/roles/${encodeURIComponent(roleName)}`,
      )
    ).body as { id: string; name: string };
    await this.adminRequest(
      'POST',
      `/admin/realms/${realm}/client-scopes/${scopeId}/scope-mappings/realm`,
      [{ id: role.id, name: role.name }],
    );
    return scopeId;
  }

  /**
   * A confidential authorization-code client (PKCE S256) for one cloud agent, with the agent's
   * scope as a default scope. No password grant, no implicit flow, no service account, no full
   * scope (its tokens carry only the agent role). Returns the secret, shown to the admin once.
   */
  async createMcpClient(
    realmName: string,
    clientId: string,
    scopeId: string,
    redirectUris: string[],
  ): Promise<string> {
    const realm = encodeURIComponent(realmName);
    const created = await this.adminRequest(
      'POST',
      `/admin/realms/${realm}/clients`,
      {
        clientId,
        protocol: 'openid-connect',
        publicClient: false,
        standardFlowEnabled: true,
        directAccessGrantsEnabled: false,
        implicitFlowEnabled: false,
        serviceAccountsEnabled: false,
        fullScopeAllowed: false,
        enabled: true,
        redirectUris,
        webOrigins: [],
        attributes: { 'pkce.code.challenge.method': 'S256' },
      },
      { returnLocation: true },
    );
    const clientUuid = created.location?.split('/').pop();
    if (!clientUuid) {
      throw new Error(`Keycloak did not return an id for client "${clientId}"`);
    }
    await this.adminRequest(
      'PUT',
      `/admin/realms/${realm}/clients/${clientUuid}/default-client-scopes/${scopeId}`,
    );
    const secret = (
      await this.adminRequest(
        'GET',
        `/admin/realms/${realm}/clients/${clientUuid}/client-secret`,
      )
    ).body as { value?: string } | undefined;
    if (!secret?.value) {
      throw new Error(
        `Keycloak did not return a secret for client "${clientId}"`,
      );
    }
    return secret.value;
  }

  /** Merges `patch` into a client's representation (redirect URIs, hardening a DCR client). */
  async updateClient(
    realmName: string,
    clientId: string,
    patch: Partial<KeycloakClientRepresentation>,
  ): Promise<void> {
    const client = await this.findClient(realmName, clientId);
    if (!client) throw new Error(`Keycloak client "${clientId}" not found`);
    await this.adminRequest(
      'PUT',
      `/admin/realms/${encodeURIComponent(realmName)}/clients/${client.id}`,
      { ...client, ...patch },
    );
  }

  /** Best effort clean-up: each call ignores a missing object. */
  async deleteClient(realmName: string, clientId: string): Promise<void> {
    const client = await this.findClient(realmName, clientId);
    if (client) {
      await this.adminRequest(
        'DELETE',
        `/admin/realms/${encodeURIComponent(realmName)}/clients/${client.id}`,
      );
    }
  }

  async deleteClientScope(realmName: string, name: string): Promise<void> {
    const id = await this.findClientScopeId(realmName, name);
    if (id) {
      await this.adminRequest(
        'DELETE',
        `/admin/realms/${encodeURIComponent(realmName)}/client-scopes/${id}`,
      );
    }
  }

  async deleteRealmRole(realmName: string, roleName: string): Promise<void> {
    if (await this.realmRoleExists(realmName, roleName)) {
      await this.adminRequest(
        'DELETE',
        `/admin/realms/${encodeURIComponent(realmName)}/roles/${encodeURIComponent(roleName)}`,
      );
    }
  }

  /**
   * The realm's anonymous DCR policies, as Manar uses them for ChatGPT agents: "Allowed Client
   * Scopes" lists exactly the agent scopes a self-registered client may ask for, and "Trusted
   * Hosts" accepts a registration from any address but requires every redirect URI on one of
   * `hosts`. `update` gets the current agent scopes and returns the new list; when it is empty the
   * trusted hosts are removed and the policy is back to Keycloak's default (DCR closed).
   */
  async updateDcrPolicy(
    realmName: string,
    hosts: string[],
    update: (agentScopes: string[]) => string[],
  ): Promise<string[]> {
    const realm = encodeURIComponent(realmName);
    const policies = (
      await this.adminRequest(
        'GET',
        `/admin/realms/${realm}/components?type=${encodeURIComponent(
          'org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy',
        )}`,
      )
    ).body as Array<{
      id: string;
      providerId: string;
      subType?: string;
      config?: Record<string, string[]>;
    }>;
    const find = (providerId: string) => {
      const policy = policies.find(
        (p) => p.providerId === providerId && p.subType === 'anonymous',
      );
      if (!policy) {
        throw new Error(
          `Realm "${realmName}" has no anonymous ${providerId} policy`,
        );
      }
      return policy;
    };
    const scopesPolicy = find('allowed-client-templates');
    const trusted = find('trusted-hosts');
    const current = scopesPolicy.config?.['allowed-client-scopes'] ?? [];
    const agentScopes = update(
      current.filter((s) => s.startsWith('manar-mcp-')),
    );
    const others = current.filter((s) => !s.startsWith('manar-mcp-'));
    await this.adminRequest(
      'PUT',
      `/admin/realms/${realm}/components/${scopesPolicy.id}`,
      {
        ...scopesPolicy,
        config: {
          ...scopesPolicy.config,
          'allowed-client-scopes': [...others, ...agentScopes],
        },
      },
    );
    const otherHosts = (trusted.config?.['trusted-hosts'] ?? []).filter(
      (h) => !hosts.includes(h),
    );
    const open = agentScopes.length > 0;
    await this.adminRequest(
      'PUT',
      `/admin/realms/${realm}/components/${trusted.id}`,
      {
        ...trusted,
        config: {
          ...trusted.config,
          'trusted-hosts': open ? [...otherHosts, ...hosts] : otherHosts,
          // Open: ChatGPT registers from addresses no one can list. Closed: Keycloak's default.
          'host-sending-registration-request-must-match': [
            open ? 'false' : 'true',
          ],
          'client-uris-must-match': ['true'],
        },
      },
    );
    return agentScopes;
  }

  /**
   * The first broker login flow Manar gives an identity provider: "Create User If Unique" only.
   * A brokered identity whose email or username matches an existing account is refused, never
   * linked to it (no linking by email, no "confirm link" step). Idempotent.
   */
  async ensureCreateOnlyFirstBrokerFlow(realmName: string): Promise<string> {
    const realm = encodeURIComponent(realmName);
    const flows = (
      await this.adminRequest(
        'GET',
        `/admin/realms/${realm}/authentication/flows`,
      )
    ).body as Array<{ alias: string }>;
    if (!flows.some((f) => f.alias === CREATE_ONLY_BROKER_FLOW)) {
      await this.adminRequest(
        'POST',
        `/admin/realms/${realm}/authentication/flows`,
        {
          alias: CREATE_ONLY_BROKER_FLOW,
          description:
            'Manar: create a new user for a brokered identity, never link by email',
          providerId: 'basic-flow',
          topLevel: true,
          builtIn: false,
        },
      );
      await this.adminRequest(
        'POST',
        `/admin/realms/${realm}/authentication/flows/${encodeURIComponent(CREATE_ONLY_BROKER_FLOW)}/executions/execution`,
        { provider: 'idp-create-user-if-unique' },
      );
    }
    const executions = (
      await this.adminRequest(
        'GET',
        `/admin/realms/${realm}/authentication/flows/${encodeURIComponent(CREATE_ONLY_BROKER_FLOW)}/executions`,
      )
    ).body as Array<{ id: string; providerId?: string; requirement: string }>;
    for (const execution of executions) {
      if (execution.requirement !== 'REQUIRED') {
        await this.adminRequest(
          'PUT',
          `/admin/realms/${realm}/authentication/flows/${encodeURIComponent(CREATE_ONLY_BROKER_FLOW)}/executions`,
          { ...execution, requirement: 'REQUIRED' },
        );
      }
    }
    return CREATE_ONLY_BROKER_FLOW;
  }

  /**
   * Creates or updates an OIDC identity provider. Emails from it are not trusted, and its first
   * login uses `ensureCreateOnlyFirstBrokerFlow`, so it can never take over an existing account.
   * Brokered users are keyed on the provider's `sub`. The client secret goes to Keycloak only.
   */
  async upsertOidcIdentityProvider(
    realmName: string,
    alias: string,
    input: {
      displayName: string;
      issuer: string;
      authorizationUrl: string;
      tokenUrl: string;
      jwksUrl: string;
      logoutUrl?: string;
      clientId: string;
      clientSecret: string;
    },
  ): Promise<void> {
    const realm = encodeURIComponent(realmName);
    const flow = await this.ensureCreateOnlyFirstBrokerFlow(realmName);
    const representation = {
      alias,
      displayName: input.displayName,
      providerId: 'oidc',
      enabled: true,
      trustEmail: false,
      linkOnly: false,
      firstBrokerLoginFlowAlias: flow,
      config: {
        clientId: input.clientId,
        clientSecret: input.clientSecret,
        clientAuthMethod: 'client_secret_post',
        authorizationUrl: input.authorizationUrl,
        tokenUrl: input.tokenUrl,
        ...(input.logoutUrl ? { logoutUrl: input.logoutUrl } : {}),
        issuer: input.issuer,
        jwksUrl: input.jwksUrl,
        useJwksUrl: 'true',
        validateSignature: 'true',
        pkceEnabled: 'true',
        pkceMethod: 'S256',
        defaultScope: 'openid profile email',
        syncMode: 'IMPORT',
      },
    };
    try {
      await this.adminRequest(
        'POST',
        `/admin/realms/${realm}/identity-provider/instances`,
        representation,
      );
    } catch (error) {
      if (!(error instanceof Error) || !error.message.includes('HTTP 409'))
        throw error;
      await this.adminRequest(
        'PUT',
        `/admin/realms/${realm}/identity-provider/instances/${encodeURIComponent(alias)}`,
        representation,
      );
    }
  }

  async identityProviderExists(
    realmName: string,
    alias: string,
  ): Promise<boolean> {
    try {
      await this.adminRequest(
        'GET',
        `/admin/realms/${encodeURIComponent(realmName)}/identity-provider/instances/${encodeURIComponent(alias)}`,
      );
      return true;
    } catch (error) {
      if (isNotFound(error)) return false;
      throw error;
    }
  }

  /** Gives `roleName` to brokered users whose `groups` claim contains `groupId` (Entra groups). */
  async addGroupRoleMapper(
    realmName: string,
    alias: string,
    name: string,
    groupId: string,
    roleName: string,
  ): Promise<void> {
    await this.adminRequest(
      'POST',
      `/admin/realms/${encodeURIComponent(realmName)}/identity-provider/instances/${encodeURIComponent(alias)}/mappers`,
      {
        name,
        identityProviderAlias: alias,
        identityProviderMapper: 'oidc-role-idp-mapper',
        config: {
          syncMode: 'FORCE',
          claim: 'groups',
          'claim.value': groupId,
          role: roleName,
        },
      },
    );
  }

  async deleteIdpMapper(
    realmName: string,
    alias: string,
    name: string,
  ): Promise<void> {
    const base = `/admin/realms/${encodeURIComponent(realmName)}/identity-provider/instances/${encodeURIComponent(alias)}/mappers`;
    let mappers: Array<{ id: string; name: string }>;
    try {
      mappers = (await this.adminRequest('GET', base)).body as typeof mappers;
    } catch (error) {
      if (isNotFound(error)) return;
      throw error;
    }
    for (const mapper of mappers.filter((m) => m.name === name)) {
      await this.adminRequest('DELETE', `${base}/${mapper.id}`);
    }
  }

  /**
   * Fetches an admin access token for the master realm using the bootstrap
   * admin's username/password (Resource Owner Password Credentials grant
   * against the `admin-cli` client, Keycloak's documented pattern for
   * scripted/automated admin access).
   */
  private async getAdminToken(): Promise<string> {
    const username = this.configService.get('KEYCLOAK_ADMIN_USERNAME', {
      infer: true,
    });
    const password = this.configService.get('KEYCLOAK_ADMIN_PASSWORD', {
      infer: true,
    });
    const clientId = this.configService.get('KEYCLOAK_ADMIN_CLIENT_ID', {
      infer: true,
    });

    const response = await fetch(
      `${this.baseUrl}/realms/master/protocol/openid-connect/token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'password',
          client_id: clientId,
          username,
          password,
        }),
      },
    );

    if (!response.ok) {
      // Deliberately does not include the response body: it could echo
      // back request parameters. Never log credentials.
      throw new Error(
        `Failed to obtain a Keycloak admin token (HTTP ${response.status})`,
      );
    }

    const body = (await response.json()) as { access_token?: string };
    if (!body.access_token) {
      throw new Error('Keycloak admin token response had no access_token');
    }
    return body.access_token;
  }

  private async adminRequest(
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    path: string,
    body?: unknown,
    options?: { returnLocation?: boolean },
  ): Promise<{ body: unknown; location?: string }> {
    const token = await this.getAdminToken();

    const response = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    if (!response.ok) {
      const text = await response.text().catch(() => '');
      this.logger.error(
        `Keycloak Admin API ${method} ${path} failed: HTTP ${response.status}`,
      );
      throw new Error(
        `Keycloak Admin API ${method} ${path} failed with HTTP ${response.status}${
          text ? `: ${text}` : ''
        }`,
      );
    }

    if (response.status === 204 || response.status === 201) {
      return {
        body: undefined,
        location: options?.returnLocation
          ? (response.headers.get('location') ?? undefined)
          : undefined,
      };
    }

    const contentType = response.headers.get('content-type') ?? '';
    if (contentType.includes('application/json')) {
      return { body: await response.json() };
    }
    return { body: undefined };
  }
}
