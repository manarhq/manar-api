import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppConfig } from '../config/env.validation';

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
