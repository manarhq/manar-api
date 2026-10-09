import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  decodeJwt,
  errors as joseErrors,
  jwtVerify,
  type JWTPayload,
} from 'jose';
import type { AppConfig } from '../config/env.validation';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { isRoleName, RoleName } from './roles';
import { KnownIssuerRegistry } from './known-issuer-registry.service';
import { JwksCacheService } from './jwks-cache.service';
import { RequestWithAuthContext } from './auth-context';

/**
 * The only JWS algorithms this deployment will ever accept a human token
 * under. Pinning matters because `jose.jwtVerify` otherwise accepts
 * whatever the token's own `alg` header asks for, which is
 * attacker-controlled input: the classic outcome is an algorithm-confusion
 * attack where a token asks to be verified symmetrically (`HS*`) against
 * key material the verifier only ever meant to use as an *asymmetric
 * public* key — public key material that this very guard hands out to
 * anyone who asks, since a realm's JWKS document is a public endpoint.
 *
 * The RSA family is the right pin for this deployment specifically:
 * `TenantProvisioningService` creates every realm with
 * `KeycloakAdminClient.createRealm`, which sets no
 * `defaultSignatureAlgorithm`, so Keycloak (26.x, see
 * `deploy/docker-compose.yml`) signs with its default `RS256` from the
 * realm's auto-generated `rsa-generated` key provider — no EC key provider
 * is ever created, so `ES*` is deliberately absent. `RS384`/`RS512` are
 * included because they are the same key provider's other permitted
 * settings: an operator raising a realm's signature algorithm is a
 * strengthening change that must not lock every human out of the product,
 * whereas anything outside this list would be a change this deployment
 * never makes.
 */
export const ACCEPTED_SIGNING_ALGORITHMS = ['RS256', 'RS384', 'RS512'] as const;

/**
 * Keycloak stamps every token it mints with a `typ` *payload* claim naming
 * what kind of token it is — `Bearer` for an access token, `ID` for an ID
 * token, `Refresh`/`Offline` for refresh tokens. (This is Keycloak's own
 * claim, not the JWS header's `typ` parameter, which is just `JWT`.)
 *
 * Only an access token is a credential for calling an API. An ID token is
 * a statement *about* an authenticated user issued for a client to consume
 * locally at the end of a login flow — it carries the same `sub`, the same
 * `realm_access.roles`, and the same realm signature, so without this check
 * a browser-side ID token (a value `manar-web` legitimately holds, and one
 * that is far more widely handled than an access token) would authenticate
 * against every endpoint in this API.
 */
const ACCESS_TOKEN_TYPE = 'Bearer';

/**
 * There is deliberately **no** `clockTolerance` on token verification.
 *
 * A skew allowance was tried and removed. It is superficially reasonable —
 * Keycloak and `manar-api` are separate processes with independently
 * drifting clocks — but it buys tolerance for a problem this deployment
 * does not have, at a cost this product cannot justify:
 *
 *  - In the supported topology both run inside one customer's dedicated
 *    deployment against the same NTP sources. Observed skew is sub-second;
 *    a tolerance sized to be useful (tens of seconds) is orders of
 *    magnitude larger than the drift it is compensating for.
 *  - Whatever the tolerance is, it is exactly the extra time a *genuinely
 *    expired* token keeps working. On a platform whose value proposition
 *    is that authorization decisions are trustworthy and auditable, silently
 *    honouring expired credentials is the wrong side to err on.
 *  - `test/auth.e2e-spec.ts`'s "an expired token is rejected" case issues a
 *    1-second token and asserts a 401 after 2.5 seconds. A tolerance large
 *    enough to be worth having necessarily breaks that test — and the
 *    honest reading of that is that the test is right, not that the
 *    assertion should be relaxed to fit the change.
 *
 * If real clock skew ever becomes a problem here, the fix is to correct the
 * clocks, not to accept expired tokens.
 */

/**
 * Validates `Authorization: Bearer <JWT>` against a *dynamic, per-issuer*
 * JWKS endpoint and attaches a trustworthy `AuthContext` to the request.
 *
 * Pipeline (see docs/human-auth.md for the full rationale):
 *   1. Extract the bearer token; missing/malformed header → 401.
 *   2. Read the token's `iss` claim WITHOUT verifying the signature yet
 *      (`decodeJwt` only base64-decodes; it's needed before verification
 *      because the realm — and therefore the JWKS URL — varies per
 *      tenant, so we don't yet know which key set to fetch or trust).
 *   3. Resolve that issuer against `KnownIssuerRegistry` (backed by the
 *      control DB's `Tenant.keycloakIssuerUrl`) — an allow-list, not a
 *      blind trust of the token. No match → 401. This is the step that
 *      guarantees the guard only ever fetches JWKS for a realm this
 *      deployment actually provisioned, never an attacker-supplied URL.
 *   4. Verify signature + expiry + issuer match against that realm's real
 *      JWKS (`jose.jwtVerify`, which also re-checks `iss` itself), with
 *      the signing algorithm pinned to `ACCEPTED_SIGNING_ALGORITHMS` and
 *      no clock-skew allowance (see above). Any failure (bad
 *      signature, unexpected algorithm, expired, wrong issuer) → 401.
 *   5. Check what the verified token *is* and *who it was issued to*
 *      (`checkTokenIsAnAccessTokenForThisClient`) — a valid realm
 *      signature alone is not enough, see that function's doc comment.
 *   6. Resolve the tenant's Prisma client (`TenantDatabaseManager`),
 *      find-or-create the `UserProfile` by `keycloakSubject` (the JWT
 *      `sub` claim), load `RoleBinding`s, attach `AuthContext`.
 *
 * Every failure path throws `UnauthorizedException`, which Nest's default
 * exception filter renders as `{ statusCode: 401, message }` with no
 * stack trace in the response body (stack traces are only ever logged
 * server-side, via `this.logger`, never serialized to the client).
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  private readonly logger = new Logger(JwtAuthGuard.name);

  constructor(
    private readonly knownIssuerRegistry: KnownIssuerRegistry,
    private readonly jwksCache: JwksCacheService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
    private readonly configService: ConfigService<AppConfig, true>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<RequestWithAuthContext>();

    const token = extractBearerToken(request.headers.authorization);
    if (!token) {
      throw new UnauthorizedException(
        'Missing or malformed Authorization header',
      );
    }

    const unverifiedIssuer = readUnverifiedIssuer(token);
    if (!unverifiedIssuer) {
      throw new UnauthorizedException('Token has no issuer claim');
    }

    const knownIssuer =
      await this.knownIssuerRegistry.resolveByIssuer(unverifiedIssuer);
    if (!knownIssuer) {
      this.logger.warn(
        `Rejected token with unrecognized issuer "${unverifiedIssuer}"`,
      );
      throw new UnauthorizedException('Unrecognized token issuer');
    }

    const jwks = this.jwksCache.getJwks(knownIssuer.issuerUrl);

    let subject: string;
    let email: string | undefined;
    let displayName: string | undefined;
    let claimedRoles: RoleName[];
    try {
      const { payload } = await jwtVerify(token, jwks, {
        issuer: knownIssuer.issuerUrl,
        algorithms: [...ACCEPTED_SIGNING_ALGORITHMS],
      });

      const rejectionReason = checkTokenIsAnAccessTokenForThisClient(
        payload,
        this.configService.get('KEYCLOAK_CLIENT_ID', { infer: true }),
      );
      if (rejectionReason) {
        this.logger.warn(
          `Rejected token for issuer "${knownIssuer.issuerUrl}": ${rejectionReason}`,
        );
        throw new UnauthorizedException('Invalid token');
      }

      if (typeof payload.sub !== 'string' || !payload.sub) {
        throw new UnauthorizedException('Token has no subject claim');
      }
      subject = payload.sub;
      email = typeof payload.email === 'string' ? payload.email : undefined;
      displayName =
        typeof payload.name === 'string'
          ? payload.name
          : typeof payload.preferred_username === 'string'
            ? payload.preferred_username
            : undefined;
      claimedRoles = extractRealmRoles(payload);
    } catch (error) {
      if (error instanceof UnauthorizedException) throw error;
      if (error instanceof joseErrors.JOSEError) {
        this.logger.warn(
          `Rejected token for issuer "${knownIssuer.issuerUrl}": ${error.code}`,
        );
        throw new UnauthorizedException('Invalid token');
      }
      throw error;
    }

    const tenantClient = await this.tenantDatabaseManager.getClient(
      knownIssuer.tenantId,
    );

    const userProfile = await tenantClient.userProfile.upsert({
      where: { keycloakSubject: subject },
      create: {
        keycloakSubject: subject,
        email: email ?? '',
        displayName: displayName ?? subject,
      },
      update: {
        lastSeenAt: new Date(),
        ...(email ? { email } : {}),
        ...(displayName ? { displayName } : {}),
      },
    });

    const roles = await this.syncRoleBindings(
      tenantClient,
      userProfile.id,
      claimedRoles,
    );

    request.authContext = {
      tenant: { id: knownIssuer.tenantId, slug: knownIssuer.tenantSlug },
      user: {
        id: userProfile.id,
        keycloakSubject: userProfile.keycloakSubject,
        email: userProfile.email,
        displayName: userProfile.displayName,
      },
      roles,
    };

    return true;
  }

  /**
   * Reconciles this user's `RoleBinding` rows to match the verified
   * token's `realm_access.roles` claim. Keycloak is this phase's only
   * source of truth for role *assignment* — there is no Manar-side
   * role-management API yet (out of scope: OpenFGA fine-grained
   * authorization is Phase 5). Grants any role present in the token but
   * missing locally, and revokes any local binding for a role no longer
   * present in the token, so a role removed in Keycloak takes effect on
   * the user's very next authenticated request.
   */
  private async syncRoleBindings(
    tenantClient: Awaited<ReturnType<TenantDatabaseManager['getClient']>>,
    userId: string,
    claimedRoles: RoleName[],
  ): Promise<RoleName[]> {
    const claimedRoleSet = new Set(claimedRoles);
    const existingBindings = await tenantClient.roleBinding.findMany({
      where: { userId },
    });
    const existingRoleSet = new Set(existingBindings.map((b) => b.role));

    const toGrant = claimedRoles.filter((role) => !existingRoleSet.has(role));
    const toRevoke = existingBindings.filter(
      (binding) => !claimedRoleSet.has(binding.role),
    );

    if (toGrant.length > 0) {
      await tenantClient.roleBinding.createMany({
        data: toGrant.map((role) => ({
          userId,
          role,
          grantedBy: 'keycloak:realm_access',
        })),
        // Concurrent first requests from one user both see the role missing;
        // ON CONFLICT DO NOTHING lets the second one through instead of a 500.
        skipDuplicates: true,
      });
    }
    if (toRevoke.length > 0) {
      await tenantClient.roleBinding.deleteMany({
        where: { id: { in: toRevoke.map((b) => b.id) } },
      });
    }

    return [...claimedRoleSet];
  }
}

function extractBearerToken(header: string | undefined): string | null {
  if (!header) return null;
  const match = /^Bearer\s+(.+)$/.exec(header);
  return match?.[1]?.trim() ? match[1].trim() : null;
}

function readUnverifiedIssuer(token: string): string | null {
  try {
    const claims = decodeJwt(token);
    return typeof claims.iss === 'string' && claims.iss ? claims.iss : null;
  } catch {
    return null;
  }
}

/**
 * The second half of "is this token one this API should honour", run on an
 * *already signature-verified* payload. A valid signature from an
 * allow-listed realm only proves the token came from that realm — it says
 * nothing about what the realm minted it *for*, and a Keycloak realm mints
 * plenty of tokens that are not credentials for this API: ID tokens for
 * `manar-web`'s login flow, tokens for any other client registered in the
 * same realm, refresh tokens. All of them carry the same `iss`, the same
 * `sub`, and the same `realm_access.roles` array this guard then trusts
 * verbatim to reconcile `RoleBinding` rows.
 *
 * Two independent checks, both required. Returns a short machine-readable
 * reason on rejection (logged server-side only) or `null` when the token
 * is genuinely an access token issued to this deployment's own client:
 *
 *   1. **Token kind** — `typ` must be exactly `ACCESS_TOKEN_TYPE`. A token
 *      with no `typ` at all is rejected too: every token this deployment's
 *      Keycloak issues has one, so its absence means the token did not come
 *      from a flow this API understands.
 *   2. **Issued to this client** — checked against `KEYCLOAK_CLIENT_ID`
 *      (the `clientId` `TenantProvisioningService` creates in every realm).
 *      This is deliberately `azp`-first rather than a plain `aud` match:
 *      Keycloak puts the *authorized party* — the client that actually
 *      requested the token — in `azp`, while `aud` on a default-configured
 *      access token lists the resource servers the token is meant for and
 *      is typically just `["account"]` unless an audience mapper has been
 *      added to the client. `createConfidentialClient` adds no such mapper,
 *      so requiring `aud` to contain `manar-api` would reject every token
 *      real Keycloak actually issues here and break login outright. `azp`
 *      is the claim that carries the real answer, so it is authoritative
 *      when present; `aud` is the fallback for the OIDC-standard case where
 *      a token has a single audience and `azp` is therefore omitted.
 */
function checkTokenIsAnAccessTokenForThisClient(
  payload: JWTPayload,
  expectedClientId: string,
): string | null {
  const tokenType = payload.typ;
  if (tokenType !== ACCESS_TOKEN_TYPE) {
    return `not_an_access_token:${typeof tokenType === 'string' ? tokenType : 'missing'}`;
  }

  const authorizedParty = payload.azp;
  if (typeof authorizedParty === 'string' && authorizedParty.length > 0) {
    return authorizedParty === expectedClientId
      ? null
      : `issued_to_another_client:${authorizedParty}`;
  }

  const audience = payload.aud;
  const audienceMatches = Array.isArray(audience)
    ? audience.includes(expectedClientId)
    : audience === expectedClientId;
  return audienceMatches ? null : 'audience_mismatch';
}

function extractRealmRoles(payload: unknown): RoleName[] {
  if (
    typeof payload !== 'object' ||
    payload === null ||
    !('realm_access' in payload)
  ) {
    return [];
  }
  const realmAccess = (payload as { realm_access?: unknown }).realm_access;
  if (
    typeof realmAccess !== 'object' ||
    realmAccess === null ||
    !('roles' in realmAccess)
  ) {
    return [];
  }
  const roles = (realmAccess as { roles?: unknown }).roles;
  if (!Array.isArray(roles)) return [];
  return roles.filter(
    (role): role is RoleName => typeof role === 'string' && isRoleName(role),
  );
}
