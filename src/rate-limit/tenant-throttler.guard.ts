import { Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  InjectThrottlerOptions,
  InjectThrottlerStorage,
  ThrottlerGuard,
} from '@nestjs/throttler';
import type {
  ThrottlerModuleOptions,
  ThrottlerStorage,
} from '@nestjs/throttler';
import { decodeJwt } from 'jose';
import type { RequestWithAuthContext } from '../auth/auth-context';
import { KnownIssuerRegistry } from '../auth/known-issuer-registry.service';

/**
 * Phase 12a: rate-limits the human JWT surface **per tenant**, not per
 * caller IP (`ThrottlerGuard`'s own default `getTracker`) -- a burst from
 * one tenant's dashboard users behind a shared corporate NAT/VPN egress IP
 * must not exhaust the same bucket as an unrelated tenant, and a bucket
 * keyed by tenant is exactly what stops one tenant's traffic from starving
 * another's regardless of network topology on either side.
 *
 * This guard is registered globally (`APP_GUARD`, `AppModule`), which
 * means it runs *before* any controller-level `JwtAuthGuard` -- so
 * `request.authContext` (attached by `JwtAuthGuard`) is not yet available
 * to key off directly. Instead this mirrors `JwtAuthGuard`'s own first two
 * steps exactly (`docs/human-auth.md`): read the token's `iss` claim
 * *without* verifying the signature (this is a rate-limit partition key,
 * not a trust decision -- an attacker presenting a forged token at worst
 * gets its own separate bucket, and still fails real authentication
 * immediately afterward in `JwtAuthGuard` itself), then resolve it against
 * `KnownIssuerRegistry` to a real `tenantId`. Falls back to the caller's IP
 * for any request this can't resolve a tenant for (no/malformed
 * Authorization header, unrecognized issuer, or an unauthenticated route)
 * -- rate limiting still applies, just not tenant-scoped, which is no
 * worse than the framework's own default for those cases.
 */
@Injectable()
export class TenantThrottlerGuard extends ThrottlerGuard {
  constructor(
    @InjectThrottlerOptions() options: ThrottlerModuleOptions,
    @InjectThrottlerStorage() storage: ThrottlerStorage,
    reflector: Reflector,
    private readonly knownIssuerRegistry: KnownIssuerRegistry,
  ) {
    super(options, storage, reflector);
  }

  protected override async getTracker(
    req: RequestWithAuthContext,
  ): Promise<string> {
    if (req.authContext?.tenant?.id) {
      return `tenant:${req.authContext.tenant.id}`;
    }

    const token = extractBearerToken(req.headers.authorization);
    if (token) {
      const issuer = readUnverifiedIssuer(token);
      if (issuer) {
        const knownIssuer =
          await this.knownIssuerRegistry.resolveByIssuer(issuer);
        if (knownIssuer) {
          return `tenant:${knownIssuer.tenantId}`;
        }
      }
    }

    return `ip:${req.ip}`;
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
