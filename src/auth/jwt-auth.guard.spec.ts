import { UnauthorizedException, type ExecutionContext } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import { generateKeyPair, SignJWT, type JWTVerifyGetKey } from 'jose';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import type { AppConfig } from '../config/env.validation';
import type { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import type { RequestWithAuthContext } from './auth-context';
import { JwtAuthGuard } from './jwt-auth.guard';
import type { JwksCacheService } from './jwks-cache.service';
import type { KnownIssuerRegistry } from './known-issuer-registry.service';

/**
 * Unit tests for the token-validation half of `JwtAuthGuard` — the checks
 * that decide whether an already-signature-valid JWT is a credential this
 * API should honour at all.
 *
 * `test/auth.e2e-spec.ts` covers the happy path against a *real* Keycloak
 * (per the Phase 3 testing requirement), but it structurally cannot cover
 * these cases: a real Keycloak will not mint an access token for a client
 * that was never registered, and driving it into issuing an ID token to
 * this API's endpoints would require a second client and a full
 * authorization-code flow just to produce one token. So these fabricate
 * tokens with `jose`'s `SignJWT` and hand the guard a fake JWKS resolver
 * that returns the matching key — the same "fabricate the token when a real
 * flow structurally cannot produce it" exception `test/auth.e2e-spec.ts`
 * already makes for its unrecognized-issuer and wrong-key scenarios.
 *
 * Every token below is otherwise *completely valid*: correctly signed by
 * the realm's own key, unexpired, with the right issuer and a real
 * `realm_access.roles` claim. That is the point — before this guard pinned
 * the algorithm and checked what the token is and who it was issued to,
 * every one of them authenticated and had its claimed roles written
 * straight into `RoleBinding` rows.
 *
 * Collaborators are plain in-memory fakes (no Nest DI container, no
 * database), matching `credential-broker.service.spec.ts`'s house style.
 */

const ISSUER = 'http://localhost:8081/realms/acme';
const CLIENT_ID = 'manar-api';
const TENANT = { tenantId: 'tenant-1', tenantSlug: 'acme', issuerUrl: ISSUER };

let signingKey: CryptoKey;
let verificationKey: CryptoKey;

beforeAll(async () => {
  const { privateKey, publicKey } = await generateKeyPair('RS256', {
    extractable: true,
  });
  signingKey = privateKey;
  verificationKey = publicKey;
});

/**
 * The shape a real Keycloak 26 access token actually has for this
 * deployment: `typ: "Bearer"`, the requesting client in `azp`, and an
 * `aud` of `["account"]` — *not* the client id, because
 * `KeycloakAdminClient.createConfidentialClient` registers no audience
 * mapper. Every test below starts from this and changes one thing.
 */
function keycloakAccessTokenClaims(): Record<string, unknown> {
  return {
    typ: 'Bearer',
    azp: CLIENT_ID,
    aud: ['account'],
    sub: 'keycloak-subject-1',
    email: 'operator@acme.test',
    preferred_username: 'operator',
    realm_access: { roles: ['SECURITY_ADMIN', 'offline_access'] },
  };
}

async function signToken(
  claims: Record<string, unknown>,
  options: { alg?: string; key?: CryptoKey | Uint8Array } = {},
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: options.alg ?? 'RS256' })
    .setIssuer(ISSUER)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(options.key ?? signingKey);
}

function fakeTenantClient() {
  const userProfile = {
    id: 'user-1',
    keycloakSubject: 'keycloak-subject-1',
    email: 'operator@acme.test',
    displayName: 'operator',
  };
  const roleBindingCreateMany = vi.fn().mockResolvedValue({ count: 1 });
  const client = {
    userProfile: { upsert: vi.fn().mockResolvedValue(userProfile) },
    roleBinding: {
      findMany: vi.fn().mockResolvedValue([]),
      createMany: roleBindingCreateMany,
      deleteMany: vi.fn().mockResolvedValue({ count: 0 }),
    },
  };
  return { client, roleBindingCreateMany };
}

function makeGuard(
  options: { jwks?: JWTVerifyGetKey; clientId?: string } = {},
): {
  guard: JwtAuthGuard;
  roleBindingCreateMany: ReturnType<typeof vi.fn>;
} {
  const { client, roleBindingCreateMany } = fakeTenantClient();

  const knownIssuerRegistry = {
    resolveByIssuer: (issuer: string) =>
      Promise.resolve(issuer === ISSUER ? TENANT : null),
  } as unknown as KnownIssuerRegistry;

  const realmJwks: JWTVerifyGetKey = () => Promise.resolve(verificationKey);
  const jwksCache = {
    getJwks: () => options.jwks ?? realmJwks,
  } as unknown as JwksCacheService;

  const tenantDatabaseManager = {
    getClient: () => Promise.resolve(client),
  } as unknown as TenantDatabaseManager;

  const configService = {
    get: () => options.clientId ?? CLIENT_ID,
  } as unknown as ConfigService<AppConfig, true>;

  return {
    guard: new JwtAuthGuard(
      knownIssuerRegistry,
      jwksCache,
      tenantDatabaseManager,
      configService,
    ),
    roleBindingCreateMany,
  };
}

function contextFor(token: string): {
  context: ExecutionContext;
  request: RequestWithAuthContext;
} {
  const request = {
    headers: { authorization: `Bearer ${token}` },
  } as unknown as RequestWithAuthContext;
  const context = {
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
  return { context, request };
}

describe('JwtAuthGuard token validation', () => {
  it('accepts a real-shaped Keycloak access token and attaches the auth context', async () => {
    const { guard } = makeGuard();
    const { context, request } = contextFor(
      await signToken(keycloakAccessTokenClaims()),
    );

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(request.authContext).toEqual({
      tenant: { id: 'tenant-1', slug: 'acme' },
      user: {
        id: 'user-1',
        keycloakSubject: 'keycloak-subject-1',
        email: 'operator@acme.test',
        displayName: 'operator',
      },
      roles: ['SECURITY_ADMIN'],
    });
  });

  it('accepts a token whose single `aud` is this client and which therefore omits `azp`', async () => {
    const claims = keycloakAccessTokenClaims();
    delete claims.azp;
    const { guard } = makeGuard();
    const { context } = contextFor(
      await signToken({ ...claims, aud: CLIENT_ID }),
    );

    await expect(guard.canActivate(context)).resolves.toBe(true);
  });

  it('rejects a token issued to a different client in the same realm', async () => {
    const { guard, roleBindingCreateMany } = makeGuard();
    const { context, request } = contextFor(
      await signToken({
        ...keycloakAccessTokenClaims(),
        azp: 'some-other-client',
      }),
    );

    await expect(guard.canActivate(context)).rejects.toThrow(
      UnauthorizedException,
    );
    expect(request.authContext).toBeUndefined();
    // The whole point: its `realm_access.roles` never reached the tenant DB.
    expect(roleBindingCreateMany).not.toHaveBeenCalled();
  });

  it('rejects a token whose `aud` names another client and which has no `azp`', async () => {
    const claims = keycloakAccessTokenClaims();
    delete claims.azp;
    const { guard } = makeGuard();
    const { context } = contextFor(
      await signToken({ ...claims, aud: ['account', 'some-other-client'] }),
    );

    await expect(guard.canActivate(context)).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('rejects an ID token minted by the same realm for this same client', async () => {
    const { guard, roleBindingCreateMany } = makeGuard();
    const { context, request } = contextFor(
      await signToken({ ...keycloakAccessTokenClaims(), typ: 'ID' }),
    );

    await expect(guard.canActivate(context)).rejects.toThrow(
      UnauthorizedException,
    );
    expect(request.authContext).toBeUndefined();
    expect(roleBindingCreateMany).not.toHaveBeenCalled();
  });

  it('rejects a refresh token minted by the same realm for this same client', async () => {
    const { guard } = makeGuard();
    const { context } = contextFor(
      await signToken({ ...keycloakAccessTokenClaims(), typ: 'Refresh' }),
    );

    await expect(guard.canActivate(context)).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('rejects a token carrying no `typ` claim at all', async () => {
    const claims = keycloakAccessTokenClaims();
    delete claims.typ;
    const { guard } = makeGuard();
    const { context } = contextFor(await signToken(claims));

    await expect(guard.canActivate(context)).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('rejects a symmetrically-signed token even when the key resolver hands back the matching key', async () => {
    // Algorithm confusion: `alg: HS256` asks the verifier to treat key
    // material it only ever meant to use asymmetrically as an HMAC secret.
    // Modelled here by a resolver that hands back exactly the key the token
    // was signed with, so the *only* thing standing between this token and
    // a successful verification is the pinned algorithm list.
    const hmacKey = new Uint8Array(32).fill(7);
    const hmacJwks: JWTVerifyGetKey = () => Promise.resolve(hmacKey);
    const { guard } = makeGuard({ jwks: hmacJwks });
    const { context } = contextFor(
      await signToken(keycloakAccessTokenClaims(), {
        alg: 'HS256',
        key: hmacKey,
      }),
    );

    await expect(guard.canActivate(context)).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('rejects an expired token', async () => {
    const { guard } = makeGuard();
    const token = await new SignJWT(keycloakAccessTokenClaims())
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer(ISSUER)
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 600)
      .sign(signingKey);
    const { context } = contextFor(token);

    await expect(guard.canActivate(context)).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('rejects a token that expired seconds ago — there is no clock-skew grace', async () => {
    // Pins the deliberate absence of `clockTolerance`. A skew allowance was
    // tried and removed: whatever its size, it is exactly the extra time a
    // genuinely expired token keeps working, and `test/auth.e2e-spec.ts`
    // asserts a 1-second token is refused 2.5 seconds later. See the guard's
    // own doc comment for the full reasoning. If this test is ever changed
    // to expect acceptance, that is a security decision, not a test fix.
    const { guard } = makeGuard();
    const token = await new SignJWT(keycloakAccessTokenClaims())
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer(ISSUER)
      .setIssuedAt(Math.floor(Date.now() / 1000) - 300)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 5)
      .sign(signingKey);
    const { context } = contextFor(token);

    await expect(guard.canActivate(context)).rejects.toThrow(
      UnauthorizedException,
    );
  });
});
