import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { RequestWithAuthContext } from './auth-context';
import { MembershipService } from './membership.service';
import {
  extractBearerToken,
  TokenVerifierService,
} from './token-verifier.service';

export { ACCEPTED_SIGNING_ALGORITHMS } from './token-verifier.service';

/** The BFF sends the workspace the user picked in the switcher in this header. */
export const WORKSPACE_HEADER = 'x-manar-workspace';

export function requestedWorkspace(
  headers: Record<string, string | string[] | undefined>,
): string | undefined {
  const v = headers[WORKSPACE_HEADER];
  const value = Array.isArray(v) ? v[0] : v;
  return value?.trim() || undefined;
}

/**
 * Human auth for tenant routes (spec 4.1):
 *   1. `TokenVerifierService` verifies the bearer token (issuer allow-list, pinned algorithm,
 *      expiry, access-token kind, our client).
 *   2. `MembershipService` resolves the workspace from the caller's choice (`X-Manar-Workspace`)
 *      and their Membership. No ACTIVE Membership for an ACTIVE tenant: 403.
 *   3. Roles come from the Membership only. `realm_access` in the token is never read.
 *   4. The tenant's `UserProfile` is found or created and `AuthContext` is attached.
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly tokenVerifier: TokenVerifierService,
    private readonly memberships: MembershipService,
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
    const identity = await this.tokenVerifier.verify(token);

    const workspace = await this.memberships.resolveActive({
      issuer: identity.issuer,
      subject: identity.subject,
      requestedTenantId: requestedWorkspace(request.headers),
      boundTenantId: identity.boundTenant?.id,
    });

    const tenantClient = await this.tenantDatabaseManager.getClient(
      workspace.tenantId,
    );
    const userProfile = await tenantClient.userProfile.upsert({
      where: { keycloakSubject: identity.subject },
      create: {
        keycloakSubject: identity.subject,
        email: identity.email ?? '',
        displayName: identity.displayName ?? identity.subject,
      },
      update: {
        lastSeenAt: new Date(),
        ...(identity.email ? { email: identity.email } : {}),
        ...(identity.displayName ? { displayName: identity.displayName } : {}),
      },
    });

    request.authContext = {
      issuer: identity.issuer,
      tenant: { id: workspace.tenantId, slug: workspace.tenantSlug },
      user: {
        id: userProfile.id,
        keycloakSubject: userProfile.keycloakSubject,
        email: userProfile.email,
        displayName: userProfile.displayName,
      },
      roles: workspace.roles,
      workspaceKind: workspace.kind,
    };
    return true;
  }
}
