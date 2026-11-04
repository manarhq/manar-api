import { Injectable } from '@nestjs/common';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { entConfig } from '../common/ent-config';

/**
 * Verifies the id_token a WATCH device got from a silent sign-in: signature (issuer JWKS), iss
 * exact, aud = the WATCH client, exp, and returns the claims. The caller checks the nonce against
 * its single-use store and the Entra tenant (`tid`) against the tenant's. Throws on anything wrong.
 */
@Injectable()
export class WatchIdTokenVerifier {
  private jwks?: ReturnType<typeof createRemoteJWKSet>;

  enabled(): boolean {
    return entConfig().watchIssuer !== null;
  }

  async verify(token: string): Promise<JWTPayload> {
    const { watchIssuer, watchClientId } = entConfig();
    if (!watchIssuer) throw new Error('identity proof is not configured');
    this.jwks ??= createRemoteJWKSet(
      new URL(`${watchIssuer}/protocol/openid-connect/certs`),
    );
    const { payload } = await jwtVerify(token, this.jwks, {
      issuer: watchIssuer,
      audience: watchClientId,
      algorithms: ['RS256', 'ES256'],
      maxTokenAge: '10m',
    });
    return payload;
  }
}
