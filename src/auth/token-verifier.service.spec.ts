import { UnauthorizedException } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import { generateKeyPair, SignJWT, type JWTVerifyGetKey } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import type { AppConfig } from '../config/env.validation';
import type { ControlPrismaService } from '../database/control-prisma.service';
import type { JwksCacheService } from './jwks-cache.service';
import { KnownIssuerRegistry } from './known-issuer-registry.service';
import { parseWids, TokenVerifierService } from './token-verifier.service';

/**
 * Token checks. Tokens are fabricated with `jose` and a fake JWKS resolver (a real Keycloak will
 * not mint an ID token for this API's endpoints). Every token is otherwise valid, including a
 * `realm_access.roles` claim: roles in a token must never matter.
 */
const SHARED = 'https://auth.test/realms/manar';
const PER_INSTALL = 'https://customer.test/realms/acme';
const LEGACY = 'https://legacy.test/realms/old';
const CLIENT_ID = 'manar-api';

let signingKey: CryptoKey;
let verificationKey: CryptoKey;
let otherKey: CryptoKey;

beforeAll(async () => {
  const a = await generateKeyPair('RS256', { extractable: true });
  signingKey = a.privateKey;
  verificationKey = a.publicKey;
  otherKey = (await generateKeyPair('RS256')).privateKey;
});

function claims(): Record<string, unknown> {
  return {
    typ: 'Bearer',
    azp: CLIENT_ID,
    aud: ['account'],
    sub: 'sub-1',
    email: 'a@example.test',
    preferred_username: 'a',
    tid: 'tid-1',
    oid: 'oid-1',
    wids: ['62e90394-69f5-4237-9190-012177145e10'],
    realm_access: { roles: ['TENANT_OWNER', 'SECURITY_ADMIN'] },
  };
}

function sign(
  c: Record<string, unknown>,
  o: {
    iss?: string;
    alg?: string;
    key?: CryptoKey | Uint8Array;
    exp?: number;
  } = {},
) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT(c)
    .setProtectedHeader({ alg: o.alg ?? 'RS256' })
    .setIssuer(o.iss ?? SHARED)
    .setIssuedAt(o.exp ? now - 3600 : now)
    .setExpirationTime(o.exp ?? now + 300)
    .sign(o.key ?? signingKey);
}

function make(jwks?: JWTVerifyGetKey) {
  const control = {
    tenant: {
      findUnique: ({ where }: { where: { keycloakIssuerUrl: string } }) =>
        Promise.resolve(
          where.keycloakIssuerUrl === LEGACY
            ? { id: 't-legacy', slug: 'old', keycloakIssuerUrl: LEGACY }
            : null,
        ),
    },
  } as unknown as ControlPrismaService;
  const cfg = {
    get: (k: string) =>
      k === 'AUTH_ISSUERS' ? `${SHARED}/, ${PER_INSTALL}` : CLIENT_ID,
  } as unknown as ConfigService<AppConfig, true>;
  const cache = {
    getJwks: () => jwks ?? (() => Promise.resolve(verificationKey)),
  } as unknown as JwksCacheService;
  return new TokenVerifierService(
    new KnownIssuerRegistry(control, cfg),
    cache,
    cfg,
  );
}

describe('TokenVerifierService', () => {
  it('accepts a shared-realm access token and exposes claims but never roles', async () => {
    const id = await make().verify(await sign(claims()));
    expect(id).toMatchObject({
      subject: 'sub-1',
      tid: 'tid-1',
      oid: 'oid-1',
      issuer: SHARED,
    });
    expect(id.boundTenant).toBeUndefined();
    expect(id).not.toHaveProperty('roles');
    expect(JSON.stringify(id)).not.toContain('TENANT_OWNER');
  });

  it('accepts a per-install realm from the configured list', async () => {
    await expect(
      make().verify(await sign(claims(), { iss: PER_INSTALL })),
    ).resolves.toMatchObject({ issuer: PER_INSTALL });
  });

  it('binds a legacy per-tenant realm to its tenant', async () => {
    const id = await make().verify(await sign(claims(), { iss: LEGACY }));
    expect(id.boundTenant).toEqual({ id: 't-legacy', slug: 'old' });
  });

  it('rejects a token from an issuer that is not configured or provisioned', async () => {
    await expect(
      make().verify(
        await sign(claims(), { iss: 'https://evil.test/realms/manar' }),
      ),
    ).rejects.toThrow(UnauthorizedException);
  });

  it('rejects a token that names a trusted issuer but is signed by another key', async () => {
    const verifier = make();
    await expect(
      verifier.verify(await sign(claims(), { key: otherKey })),
    ).rejects.toThrow(UnauthorizedException);
  });

  it('accepts a single-audience token that omits azp', async () => {
    const c = claims();
    delete c.azp;
    await expect(
      make().verify(await sign({ ...c, aud: CLIENT_ID })),
    ).resolves.toBeDefined();
  });

  it.each([
    ['another client', { azp: 'other' }],
    ['an ID token', { typ: 'ID' }],
    ['a refresh token', { typ: 'Refresh' }],
  ])('rejects %s', async (_n, patch) => {
    await expect(
      make().verify(await sign({ ...claims(), ...patch })),
    ).rejects.toThrow(UnauthorizedException);
  });

  it('rejects a token with no typ, and one whose aud names another client without azp', async () => {
    const noTyp = claims();
    delete noTyp.typ;
    await expect(make().verify(await sign(noTyp))).rejects.toThrow(
      UnauthorizedException,
    );
    const noAzp = claims();
    delete noAzp.azp;
    await expect(
      make().verify(await sign({ ...noAzp, aud: ['account', 'x'] })),
    ).rejects.toThrow(UnauthorizedException);
  });

  it('rejects a symmetrically signed token even if the resolver returns the matching key', async () => {
    const hmac = new Uint8Array(32).fill(7);
    const verifier = make(() => Promise.resolve(hmac));
    await expect(
      verifier.verify(await sign(claims(), { alg: 'HS256', key: hmac })),
    ).rejects.toThrow(UnauthorizedException);
  });

  it('rejects an expired token with no clock-skew grace', async () => {
    const exp = Math.floor(Date.now() / 1000) - 5;
    await expect(make().verify(await sign(claims(), { exp }))).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('tryVerify returns null instead of throwing', async () => {
    await expect(make().tryVerify('not-a-jwt')).resolves.toBeNull();
  });
});

describe('Microsoft session claims', () => {
  it('exposes idp from the user session and parses wids sent as a session-note string', async () => {
    const id = await make().verify(
      await sign({
        ...claims(),
        idp: 'microsoft',
        wids: '[62e90394-69f5-4237-9190-012177145e10, e8611ab8-c189-46e8-94e1-60213ab1f814]',
      }),
    );
    expect(id.idp).toBe('microsoft');
    expect(id.wids).toEqual([
      '62e90394-69f5-4237-9190-012177145e10',
      'e8611ab8-c189-46e8-94e1-60213ab1f814',
    ]);
  });

  it('a session without idp (email link) has none', async () => {
    const c = claims();
    delete c.idp;
    expect((await make().verify(await sign(c))).idp).toBeUndefined();
  });

  it.each([
    [
      ['a', 'b'],
      ['a', 'b'],
    ],
    ['a b', ['a', 'b']],
    ['["a","b"]', ['a', 'b']],
    [undefined, []],
    [42, []],
  ])('parseWids(%j)', (input, expected) => {
    expect(parseWids(input)).toEqual(expected);
  });
});
