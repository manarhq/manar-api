import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
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

    return {
      subject: payload.sub,
      issuer: trusted.issuerUrl,
      email: str(payload.email),
      displayName: str(payload.name) ?? str(payload.preferred_username),
      boundTenant: trusted.boundTenant,
      tid: str(payload.tid),
      oid: str(payload.oid),
      wids: parseWids(payload.wids),
      idp: str(payload.idp),
    };
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
 * `wids` is a list in Entra's token but arrives from a Keycloak session note as one string
 * (`[a, b]` or `a b`); accept both shapes.
 */
export function parseWids(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((w): w is string => typeof w === 'string' && w !== '');
  }
  if (typeof value === 'string') {
    return value.split(/[\s,[\]"']+/).filter(Boolean);
  }
  return [];
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
