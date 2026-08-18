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
   * Creates a confidential client and returns its generated secret.
   * `directAccessGrantsEnabled: true` is set so this client also supports
   * the Resource Owner Password Credentials grant — used by this phase's
   * tests to obtain real, Keycloak-signed tokens for a realm test user
   * without fabricating a JWT. The full interactive login redirect flow
   * (`standardFlowEnabled`) is Phase 11, but enabling it here now avoids a
   * client-config migration later.
   */
  async createConfidentialClient(
    realmName: string,
    clientId: string,
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
    method: 'GET' | 'POST',
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
