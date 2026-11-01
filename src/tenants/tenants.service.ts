import { Injectable, NotFoundException } from '@nestjs/common';
import { ControlPrismaService } from '../database/control-prisma.service';

export interface TenantOidcConfig {
  tenantId: string;
  slug: string;
  realm: string;
  issuerUrl: string;
  clientId: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  endSessionEndpoint: string;
  jwksUri: string;
}

/**
 * Phase 11b Part 1 — resolves a tenant's Keycloak OIDC config, closing the
 * gap `manar-web/docs/auth-flow.md`'s "Known limitation: client secret
 * retrieval" documents (see `TenantsController`'s doc comment for the
 * full design). Reads straight from the control DB's `Tenant`/
 * `SecretReference` rows Phase 3's `TenantProvisioningService` already
 * wrote at provisioning time — never calls the live Keycloak Admin API
 * (no admin token round-trip on this path at all, unlike
 * `KeycloakAdminClient`), and never touches
 * `KEYCLOAK_ADMIN_USERNAME`/`PASSWORD`.
 */
@Injectable()
export class TenantsService {
  constructor(private readonly control: ControlPrismaService) {}

  /**
   * Public discovery info only — issuer/client ID/the standard OIDC
   * endpoint URLs a browser or BFF needs to start a login redirect. Every
   * one of these values is either already public by construction (the
   * issuer URL and JWKS URI are embedded in, and openly resolvable from,
   * every JWT this realm issues) or Keycloak's own realm discovery
   * document already serves unauthenticated
   * (`GET /realms/<realm>/.well-known/openid-configuration}` — see
   * `manar-web/docs/auth-flow.md`). This method exposes nothing a caller
   * couldn't already get by hitting Keycloak directly once it knows the
   * realm name; the value-add is that a caller only needs to know the
   * tenant's `slug`; the client *secret* is never returned here — see
   * (the client secret is no longer served by this API).
   */
  async getOidcConfigOrThrow(slug: string): Promise<TenantOidcConfig> {
    const tenant = await this.control.tenant.findUnique({ where: { slug } });
    if (!tenant || !tenant.keycloakRealm || !tenant.keycloakIssuerUrl) {
      // Same "no such workspace" posture manar-web's own realm-existence
      // check already uses (Keycloak's discovery endpoint 404s for an
      // unprovisioned/unknown realm) — deliberately generic, not
      // distinguishing "no such tenant" from "tenant exists but Keycloak
      // provisioning never completed" (see docs/human-auth.md's "Known
      // limitation: partial provisioning failure").
      throw new NotFoundException(`No provisioned tenant "${slug}" was found`);
    }

    const issuerUrl = tenant.keycloakIssuerUrl;
    return {
      tenantId: tenant.id,
      slug: tenant.slug,
      realm: tenant.keycloakRealm,
      issuerUrl,
      clientId: tenant.keycloakClientId ?? '',
      // Keycloak's standard realm-relative OIDC endpoint suffixes — the
      // same convention `KeycloakAdminClient.jwksUrlForIssuer` already
      // hardcodes for the certs endpoint (`src/keycloak/keycloak-admin.client.ts`).
      authorizationEndpoint: `${issuerUrl}/protocol/openid-connect/auth`,
      tokenEndpoint: `${issuerUrl}/protocol/openid-connect/token`,
      endSessionEndpoint: `${issuerUrl}/protocol/openid-connect/logout`,
      jwksUri: `${issuerUrl}/protocol/openid-connect/certs`,
    };
  }
}
