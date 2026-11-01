import { Controller, Get, Param } from '@nestjs/common';
import { ApiOperation, ApiParam, ApiResponse, ApiTags } from '@nestjs/swagger';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import { TenantOidcConfigResponseDto } from './tenants.dto';
import { TenantsService } from './tenants.service';

/**
 * Phase 11b Part 1 — fixes the credential-hygiene gap
 * `manar-web/docs/auth-flow.md`'s "Known limitation: client secret
 * retrieval" documents: `manar-web`'s BFF currently fetches the
 * confidential client's secret directly from Keycloak's own Admin API,
 * authenticating with a *standing copy* of the same infrastructure-
 * operator master-realm credentials
 * (`KEYCLOAK_ADMIN_USERNAME`/`PASSWORD`) `TenantProvisioningService` uses
 * — a real instance of Section 99's "minimize where privileged
 * credentials live": a second, browser-facing process now also holds
 * unrestricted Keycloak Admin API access, when all it actually needs is
 * one already-generated secret for one already-provisioned tenant.
 *
 * This controller closes that gap by having `manar-api` — which already
 * legitimately holds the one standing Keycloak admin credential, for
 * realm provisioning — proxy just the secret retrieval, split into two
 * endpoints with two entirely different trust postures:
 *
 *   - `GET /tenants/:slug/oidc-config` is genuinely public and
 *     unauthenticated (no `JwtAuthGuard` — there is no tenant JWT yet at
 *     this point in the login flow, by construction: this is exactly the
 *     "which realm do I even redirect to" step). It returns only the
 *     issuer URL, client ID, and the standard OIDC endpoint URLs derived
 *     from them — every one of these is either already embedded in, and
 *     openly resolvable from, any JWT this realm issues, or already
 *     served unauthenticated by Keycloak's own per-realm discovery
 *     document. Never the client secret.
 *   - `GET /tenants/:slug/oidc-client-secret` returns the one genuinely
 *     sensitive value, gated by `BffServiceGuard` — a narrow,
 *     single-purpose shared secret (`MANAR_BFF_SERVICE_TOKEN`) known only
 *     to `manar-api` and `manar-web`'s BFF process, never a tenant-scoped
 *     JWT role (there is none yet) and never Keycloak master-admin
 *     credentials themselves. Possessing this token can only ever read
 *     back an already-generated secret for an already-provisioned tenant
 *     — it grants none of the realm-creation/role-management/client-
 *     creation capability the master-admin credentials it replaces would.
 *     `manar-web`'s BFF calls this once, server-side, during its OIDC
 *     authorization-code exchange (`/api/auth/callback`) — the secret is
 *     never forwarded to, or observable by, the browser (see
 *     `manar-web/docs/auth-flow.md`'s BFF/token-handler design, which this
 *     endpoint slots into unchanged).
 *
 * RETIRED (spec 4.1): `GET /tenants/:slug/oidc-client-secret` and `BffServiceGuard`. manar-web now holds its
 * own OIDC client secret for the shared realm (ExternalSecret), so no endpoint hands a client secret out.
 *
 * The remaining endpoint does not use `JwtAuthGuard` — both are necessarily reachable
 * pre-login. `openapi-docs.e2e-spec.ts`'s "every documented path requires
 * bearer auth" check deliberately does not include either path in its
 * fixed list, for exactly this reason.
 */
@ApiTags('tenants')
@Controller('tenants')
export class TenantsController {
  constructor(private readonly tenantsService: TenantsService) {}

  @Get(':slug/oidc-config')
  @ApiOperation({
    summary: "Resolve a tenant's public OIDC discovery info",
    description:
      'Unauthenticated by design — needed before a human has any session (the tenant-slug login step, docs/human-auth.md). Returns only public discovery data (issuer URL, client ID, standard OIDC endpoint URLs); never the client secret.',
  })
  @ApiParam({
    name: 'slug',
    description: "The tenant's slug (== its Keycloak realm name)",
  })
  @ApiResponse({ status: 200, type: TenantOidcConfigResponseDto })
  @ApiResponse({
    status: 404,
    type: ErrorResponseDto,
    description: 'No such tenant, or its Keycloak realm was never provisioned.',
  })
  async getOidcConfig(
    @Param('slug') slug: string,
  ): Promise<TenantOidcConfigResponseDto> {
    return this.tenantsService.getOidcConfigOrThrow(slug);
  }
}
