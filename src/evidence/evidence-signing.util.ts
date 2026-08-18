import { createHash } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import { toKey } from '../approvals/grant-token.util';
import { canonicalize } from '../audit/canonical-json';

/**
 * Phase 9b (Evidence export, Section 49) — "reuse Phase 8's grant-signing
 * crypto utility rather than inventing a second signing mechanism." This
 * module deliberately reuses `src/approvals/grant-token.util.ts`'s `toKey`
 * (the exact same HS256 key derivation `signGrantToken`/`verifyGrantToken`
 * use, and the exact same `APPROVAL_GRANT_SIGNING_SECRET` config value —
 * see `EvidenceExportService`) and the same `jose` `SignJWT`/`jwtVerify`
 * mechanism, rather than a second HMAC scheme or a different signing
 * library. It's a *sibling* function to `signGrantToken`, not a call
 * through it, because an evidence bundle's payload shape is genuinely
 * different (an arbitrary, potentially-large JSON document's content hash,
 * not a fixed set of grant claims) and — unlike a short-lived
 * `AuthorizationGrant` — must remain verifiable indefinitely (no `exp`
 * claim is ever set here).
 *
 * The signature covers a `sha256(canonicalize(bundleContent))` digest
 * (reusing `src/audit/canonical-json.ts`'s deterministic canonicalization
 * — the exact same tool `computeEventHash` uses for `AuditEvent` hashing),
 * not the raw JSON text: this makes the signature verification
 * independent of incidental re-serialization (key order, whitespace)
 * while still failing for any actual content change — "tampering the
 * exported JSON after the fact makes verification fail" (Section 49's
 * mandatory test).
 */
export interface EvidenceBundleSignature {
  /** sha256 hex of `canonicalize(bundleContent)`. */
  bundleHash: string;
  /** A compact HS256 JWT over `{ bundleHash }` — the actual signature artifact a recipient verifies. */
  signature: string;
  algorithm: 'HS256';
}

export function computeBundleHash(bundleContent: unknown): string {
  return createHash('sha256')
    .update(canonicalize(bundleContent), 'utf8')
    .digest('hex');
}

export async function signEvidenceBundle(
  bundleContent: unknown,
  exportId: string,
  secret: string,
): Promise<EvidenceBundleSignature> {
  const bundleHash = computeBundleHash(bundleContent);
  const signature = await new SignJWT({ bundleHash })
    .setProtectedHeader({ alg: 'HS256' })
    .setJti(exportId)
    .setIssuedAt()
    .sign(toKey(secret));
  return { bundleHash, signature, algorithm: 'HS256' };
}

export type VerifyEvidenceBundleResult =
  { valid: true } | { valid: false; reason: string };

/**
 * Recomputes `bundleContent`'s hash and confirms it both (a) matches the
 * hash embedded in the signed JWT and (b) the JWT's own signature is
 * genuine — either check failing means the bundle was tampered with (or
 * the signature/secret don't correspond), and is reported as `{ valid:
 * false }` rather than throwing, so a caller doesn't need a try/catch to
 * distinguish "tampered" from "some other bug."
 */
export async function verifyEvidenceBundle(
  bundleContent: unknown,
  signature: string,
  secret: string,
): Promise<VerifyEvidenceBundleResult> {
  let payload: { bundleHash?: unknown };
  try {
    ({ payload } = await jwtVerify(signature, toKey(secret)));
  } catch {
    return { valid: false, reason: 'signature_invalid' };
  }

  if (typeof payload.bundleHash !== 'string') {
    return { valid: false, reason: 'signature_missing_bundle_hash' };
  }

  const recomputed = computeBundleHash(bundleContent);
  if (recomputed !== payload.bundleHash) {
    return { valid: false, reason: 'bundle_content_mismatch' };
  }

  return { valid: true };
}
