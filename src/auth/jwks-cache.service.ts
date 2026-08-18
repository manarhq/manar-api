import { Injectable } from '@nestjs/common';
import { createRemoteJWKSet } from 'jose';
import type { JWTVerifyGetKey } from 'jose';

/**
 * Caches a `jose` remote JWKS resolver per issuer URL, so a busy realm
 * doesn't refetch its JWKS document on every request — `jose`'s own
 * `createRemoteJWKSet` already caches/refreshes the fetched key set
 * internally per instance, this just avoids constructing a new instance
 * (and therefore a fresh, un-cached fetch) per request.
 *
 * Only ever called with an issuer URL that has already passed
 * `KnownIssuerRegistry`'s allow-list check — never constructed from a
 * token-supplied URL directly.
 */
@Injectable()
export class JwksCacheService {
  private readonly cache = new Map<string, JWTVerifyGetKey>();

  getJwks(issuerUrl: string): JWTVerifyGetKey {
    let jwks = this.cache.get(issuerUrl);
    if (!jwks) {
      jwks = createRemoteJWKSet(
        new URL(`${issuerUrl}/protocol/openid-connect/certs`),
      );
      this.cache.set(issuerUrl, jwks);
    }
    return jwks;
  }
}
