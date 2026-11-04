import {
  Injectable,
  Logger,
  Optional,
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
import { JwksCacheService } from './jwks-cache.service';
import { KnownIssuerRegistry } from './known-issuer-registry.service';
import { AccountsService } from '../staff/index/accounts.service';

/** Only RSA family; see the history in JwtAuthGuard's old doc comment (algorithm confusion). */
export const ACCEPTED_SIGNING_ALGORITHMS = ['RS256', 'RS384', 'RS512'] as const;

/** Keycloak's own `typ` claim: only an access token ("Bearer") is a credential for this API. */
const ACCESS_TOKEN_TYPE = 'Bearer';

/**
 * Who a verified token says the caller is. Deliberately has no roles: roles come from Membership
 * only (spec 4.1). `tid`/`oid`/`wids` are Entra claims the realm's Microsoft mapper copies in.
 */
export interface VerifiedIdentity {
  subject: string;
  issuer: string;
  email?: string;
  displayName?: string;
  /** Set only when the token came from a legacy per-tenant realm. */
  boundTenant?: { id: string; slug: string };
  tid?: string;
  oid?: string;
  wids: string[];
  /**
   * How the user signed in to Keycloak (`microsoft`, `github`), from the user session; absent for
   * an email link. Company decisions need `microsoft` AND these claims from the same session.
   */
  idp?: string;
  /** Seconds since epoch of the last interactive sign-in (`auth_time`); absent = unknown. */
  authTime?: number;
}

/**
 * Verifies a human bearer token: issuer allow-list, signature against that issuer's JWKS with the
 * algorithm pinned, expiry (no clock-skew grace), token kind, and the client it was issued to.
 * Shared by JwtAuthGuard, IdentityGuard and the tenant throttler so they cannot drift apart.
 */
@Injectable()
export class TokenVerifierService {
  private readonly logger = new Logger(TokenVerifierService.name);

  constructor(
    private readonly issuers: KnownIssuerRegistry,
    private readonly jwksCache: JwksCacheService,
    private readonly configService: ConfigService<AppConfig, true>,
    @Optional() private readonly accounts?: AccountsService,
  ) {}

  async verify(token: string): Promise<VerifiedIdentity> {
    const unverifiedIssuer = readUnverifiedIssuer(token);
    if (!unverifiedIssuer) {
      throw new UnauthorizedException('Token has no issuer claim');
    }
    const trusted = await this.issuers.resolveTrusted(unverifiedIssuer);
    if (!trusted) {
      this.logger.warn(
        `Rejected token with unrecognized issuer "${unverifiedIssuer}"`,
      );
      throw new UnauthorizedException('Unrecognized token issuer');
    }

    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(
        token,
        this.jwksCache.getJwks(trusted.issuerUrl),
        {
          issuer: trusted.issuerUrl,
          algorithms: [...ACCEPTED_SIGNING_ALGORITHMS],
        },
      ));
    } catch (error) {
      if (error instanceof joseErrors.JOSEError) {
        this.logger.warn(
          `Rejected token for issuer "${trusted.issuerUrl}": ${error.code}`,
        );
        throw new UnauthorizedException('Invalid token');
      }
      throw error;
    }

    const rejection = checkTokenIsAnAccessTokenForThisClient(
      payload,
      this.configService.get('KEYCLOAK_CLIENT_ID', { infer: true }),
    );
    if (rejection) {
      this.logger.warn(
        `Rejected token for issuer "${trusted.issuerUrl}": ${rejection}`,
      );
      throw new UnauthorizedException('Invalid token');
    }
    if (typeof payload.sub !== 'string' || !payload.sub) {
      throw new UnauthorizedException('Token has no subject claim');
    }

    const identity: VerifiedIdentity = {
      subject: payload.sub,
      issuer: trusted.issuerUrl,
      email: str(payload.email),
      displayName: str(payload.name) ?? str(payload.preferred_username),
      boundTenant: trusted.boundTenant,
      tid: str(payload.tid),
      oid: str(payload.oid),
      wids: entraAdminWids(payload),
      idp: str(payload.idp),
      authTime:
        typeof payload.auth_time === 'number' ? payload.auth_time : undefined,
    };
    // DESK account index (spec §17.1): at most once per 10 minutes, never fails the request.
    void this.accounts?.touch(identity);
    return identity;
  }

  /** For callers that only partition by identity (throttler): null instead of throwing. */
  async tryVerify(token: string): Promise<VerifiedIdentity | null> {
    try {
      return await this.verify(token);
    } catch {
      return null;
    }
  }
}

export function extractBearerToken(header: string | undefined): string | null {
  if (!header) return null;
  const match = /^Bearer\s+(.+)$/.exec(header);
  return match?.[1]?.trim() ? match[1].trim() : null;
}

/**
 * Entra directory-role ids the caller held at their LAST Microsoft sign-in. Keycloak's Microsoft
 * mappers (realm-manar.yaml, `oidc-role-idp-mapper`, FORCE) grant or remove exactly two realm roles
 * from the `wids` claim on every sign-in; this reads only those two names from `realm_access`.
 * No other role in the token is ever read, and company decisions additionally need `idp=microsoft`
 * for the current session.
 */
const ENTRA_ADMIN_ROLES: Record<string, string> = {
  'entra-global-admin': '62e90394-69f5-4237-9190-012177145e10',
  'entra-privileged-role-admin': 'e8611ab8-c189-46e8-94e1-60213ab1f814',
};

export function entraAdminWids(payload: JWTPayload): string[] {
  const access = payload.realm_access as { roles?: unknown } | undefined;
  const roles = Array.isArray(access?.roles) ? access.roles : [];
  return roles.flatMap((r) =>
    typeof r === 'string' && Object.hasOwn(ENTRA_ADMIN_ROLES, r)
      ? [ENTRA_ADMIN_ROLES[r]!]
      : [],
  );
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v ? v : undefined;
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
 * `azp` first (Keycloak puts the requesting client there; `aud` is usually just `account`), `aud`
 * as the fallback for a single-audience token.
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
