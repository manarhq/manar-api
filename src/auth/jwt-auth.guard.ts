import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { decodeJwt, errors as joseErrors, jwtVerify } from 'jose';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { isRoleName, RoleName } from './roles';
import { KnownIssuerRegistry } from './known-issuer-registry.service';
import { JwksCacheService } from './jwks-cache.service';
import { RequestWithAuthContext } from './auth-context';

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
 *      JWKS (`jose.jwtVerify`, which also re-checks `iss` itself). Any
 *      failure (bad signature, expired, wrong issuer) → 401.
 *   5. Resolve the tenant's Prisma client (`TenantDatabaseManager`),
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
      });
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
