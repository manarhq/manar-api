import { SignJWT, jwtVerify } from 'jose';

export interface GrantTokenClaims {
  /** The `AuthorizationGrant.id` this token names — also its JWT `jti`. */
  jti: string;
  tenantId: string;
  agentId: string;
  taskId: string;
  toolId: string;
  actionId: string;
  resource: string;
  parameterHash: string;
}

/**
 * Exported (Phase 9b) so `src/evidence/evidence-signing.util.ts` can reuse
 * the exact same HS256 key-derivation this module's own
 * `signGrantToken`/`verifyGrantToken` use, rather than a second,
 * independently-typed derivation of the same secret — see that file's doc
 * comment. Purely additive: `signGrantToken`/`verifyGrantToken` themselves
 * are unchanged.
 */
export function toKey(secret: string): Uint8Array {
  return new TextEncoder().encode(secret);
}

/**
 * Signs an `AuthorizationGrant`'s token (Section 31) from its *already
 * persisted* fields, deterministically — `issuedAt`/`expiresAt` are
 * embedded as the JWT's own `iat`/`exp` (not "now"), so signing the exact
 * same row's fields twice with the exact same secret always produces the
 * exact same signature. This is why `AuthorizationGrant` itself has no
 * `token` column (see that model's schema doc comment): the token is
 * re-derivable on demand from the row rather than a second, redundant
 * source of truth that could drift from it.
 */
export async function signGrantToken(
  grant: GrantTokenClaims & { issuedAt: Date; expiresAt: Date },
  secret: string,
): Promise<string> {
  return new SignJWT({
    tenantId: grant.tenantId,
    agentId: grant.agentId,
    taskId: grant.taskId,
    toolId: grant.toolId,
    actionId: grant.actionId,
    resource: grant.resource,
    parameterHash: grant.parameterHash,
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setJti(grant.jti)
    .setIssuedAt(Math.floor(grant.issuedAt.getTime() / 1000))
    .setExpirationTime(Math.floor(grant.expiresAt.getTime() / 1000))
    .sign(toKey(secret));
}

/**
 * Verifies an `AuthorizationGrant` token's signature and embedded
 * expiry (`jose`'s own `jwtVerify` rejects an expired token outright) and
 * returns its decoded claims. Throws on any invalid/malformed/expired
 * token or missing claim — callers must treat any thrown error as "this
 * grant is not usable," never assume success from the absence of a throw
 * alone without also checking the returned claims.
 */
export async function verifyGrantToken(
  token: string,
  secret: string,
): Promise<GrantTokenClaims> {
  const { payload } = await jwtVerify(token, toKey(secret));

  const jti = payload.jti;
  const {
    tenantId,
    agentId,
    taskId,
    toolId,
    actionId,
    resource,
    parameterHash,
  } = payload as Record<string, unknown>;

  if (
    typeof jti !== 'string' ||
    typeof tenantId !== 'string' ||
    typeof agentId !== 'string' ||
    typeof taskId !== 'string' ||
    typeof toolId !== 'string' ||
    typeof actionId !== 'string' ||
    typeof resource !== 'string' ||
    typeof parameterHash !== 'string'
  ) {
    throw new Error('Grant token is missing one or more required claims');
  }

  return {
    jti,
    tenantId,
    agentId,
    taskId,
    toolId,
    actionId,
    resource,
    parameterHash,
  };
}
