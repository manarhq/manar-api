import {
  ForbiddenException,
  ServiceUnavailableException,
  UnauthorizedException,
  type ExecutionContext,
} from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import { generateKeyPair, SignJWT, type JWTVerifyGetKey } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import type { AppConfig } from '../config/env.validation';
import type { JwksCacheService } from '../auth/jwks-cache.service';
import { PlatformAuthGuard } from './platform-auth.guard';

const ISSUER = 'http://localhost:8081/realms/master';
let signingKey: CryptoKey;
let otherKey: CryptoKey;
let verificationKey: CryptoKey;

beforeAll(async () => {
  const pair = await generateKeyPair('RS256');
  signingKey = pair.privateKey;
  verificationKey = pair.publicKey;
  otherKey = (await generateKeyPair('RS256')).privateKey;
});

function guard(
  issuer: string | undefined = ISSUER,
  jwks: JWTVerifyGetKey = () => Promise.resolve(verificationKey),
) {
  const values: Record<string, unknown> = {
    PLATFORM_API_ISSUER: issuer,
    PLATFORM_API_CLIENT_ID: 'manar-fleet',
    PLATFORM_API_ROLE: 'manar-platform-admin',
  };
  const config = { get: (k: string) => values[k] } as unknown as ConfigService<
    AppConfig,
    true
  >;
  const cache = { getJwks: () => jwks } as unknown as JwksCacheService;
  return new PlatformAuthGuard(config, cache);
}

function ctx(authorization?: string): ExecutionContext {
  const request = { headers: { authorization } };
  return {
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
}

function token(
  claims: Record<string, unknown> = {},
  o: { iss?: string; exp?: number | string; key?: CryptoKey } = {},
) {
  return new SignJWT({
    typ: 'Bearer',
    azp: 'manar-fleet',
    realm_access: { roles: ['manar-platform-admin'] },
    ...claims,
  })
    .setProtectedHeader({ alg: 'RS256' })
    .setSubject('service-account-manar-fleet')
    .setIssuer(o.iss ?? ISSUER)
    .setIssuedAt()
    .setExpirationTime(o.exp ?? '5m')
    .sign(o.key ?? signingKey);
}

describe('PlatformAuthGuard', () => {
  it('accepts a platform token with the role', async () => {
    await expect(
      guard().canActivate(ctx(`Bearer ${await token()}`)),
    ).resolves.toBe(true);
  });

  it('is off (503) when PLATFORM_API_ISSUER is unset', async () => {
    await expect(
      guard('').canActivate(ctx(`Bearer ${await token()}`)),
    ).rejects.toBeInstanceOf(ServiceUnavailableException);
  });

  it('rejects a missing token, another issuer, an expired token and a foreign key', async () => {
    const bad = [
      undefined,
      `Bearer ${await token({}, { iss: 'http://localhost:8081/realms/acme' })}`,
      `Bearer ${await token({}, { exp: Math.floor(Date.now() / 1000) - 60 })}`,
      `Bearer ${await token({}, { key: otherKey })}`,
    ];
    for (const h of bad)
      await expect(guard().canActivate(ctx(h))).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
  });

  it('rejects a token issued to another client or not an access token', async () => {
    for (const claims of [{ azp: 'manar-web' }, { typ: 'ID' }])
      await expect(
        guard().canActivate(ctx(`Bearer ${await token(claims)}`)),
      ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('forbids a token without the platform role', async () => {
    await expect(
      guard().canActivate(
        ctx(`Bearer ${await token({ realm_access: { roles: ['admin'] } })}`),
      ),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('fails closed with 503 when the JWKS is unreachable', async () => {
    const down: JWTVerifyGetKey = () =>
      Promise.reject(new TypeError('fetch failed'));
    await expect(
      guard(ISSUER, down).canActivate(ctx(`Bearer ${await token()}`)),
    ).rejects.toBeInstanceOf(ServiceUnavailableException);
  });
});
