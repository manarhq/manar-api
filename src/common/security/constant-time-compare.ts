import { createHash, timingSafeEqual } from 'node:crypto';

/**
 * The one shared secret-comparison primitive for this codebase's
 * header-carried shared credentials — `BffServiceGuard`
 * (`MANAR_BFF_SERVICE_TOKEN`, the *only* credential on
 * `GET /tenants/:slug/oidc-client-secret`) and `PlatformOperatorGuard`
 * (`PLATFORM_KILL_SWITCH_OPERATOR_TOKEN`, the platform-wide kill switch).
 * Both previously used a plain `!==`, which V8 implements as a byte-wise
 * comparison that returns as soon as it finds a mismatching byte: an
 * attacker who can time enough requests recovers the expected token one
 * byte at a time, and both of those tokens are long-lived shared secrets
 * with no second factor behind them.
 *
 * `node:crypto`'s `timingSafeEqual` is the correct primitive but has a
 * hard precondition — it *throws* on buffers of differing length, so
 * every naive call site guards it with an `if (a.length !== b.length)
 * return false`, which is itself an early return that leaks the expected
 * secret's exact length. `src/webhooks/webhook-signing.ts`'s
 * `verifyWebhookSignature` can legitimately do that (an HMAC-SHA256 hex
 * digest is a fixed 71 bytes there, so a length mismatch reveals only
 * that the caller sent something that is not a signature at all), but a
 * shared token has no fixed length and its length is genuinely secret.
 *
 * So both sides are hashed to a fixed-width SHA-256 digest *first* and
 * the two 32-byte digests are what `timingSafeEqual` compares. The
 * hashing step runs over the full input on both sides regardless of any
 * mismatch, the digests are always the same length so `timingSafeEqual`
 * never throws and is never guarded by a length check, and the comparison
 * itself is constant time. Equal digests imply equal inputs for any
 * attacker who cannot produce a SHA-256 collision — which is a strictly
 * stronger assumption than the one this codebase already makes by signing
 * webhooks with HMAC-SHA256.
 *
 * This is *not* a password/KDF primitive (there is no salt and no work
 * factor, deliberately): it compares two high-entropy secrets that are
 * already both in memory, never a low-entropy user-chosen value against
 * a stored digest.
 */
export function constantTimeEqual(provided: string, expected: string): boolean {
  const providedDigest = createHash('sha256').update(provided, 'utf8').digest();
  const expectedDigest = createHash('sha256').update(expected, 'utf8').digest();
  return timingSafeEqual(providedDigest, expectedDigest);
}
