import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Phase 12a (Section 51) webhook signing scheme — documented in full at
 * docs/security.md, reproduced here as the one place it's actually
 * implemented so the two can never drift:
 *
 *   `Manar-Signature: sha256=<hex HMAC-SHA256(secret, "<timestamp>.<body>")>`
 *   `Manar-Timestamp: <unix milliseconds the request was signed at>`
 *
 * The timestamp is signed *together with* the body (not sent unsigned
 * alongside it) specifically so an attacker who captured a real, validly
 * signed delivery cannot replay it later with a freshly forged timestamp —
 * changing `Manar-Timestamp` without knowing `secret` invalidates the
 * signature. A receiver is expected to reject any request whose
 * `Manar-Timestamp` is more than `WEBHOOK_SIGNATURE_TOLERANCE_MS` away from
 * its own clock (`verifyWebhookSignature`'s `toleranceMs` — this is this
 * scheme's replay-protection window), independent of and in addition to
 * verifying the signature itself.
 */
export interface SignedWebhookRequest {
  signatureHeader: string;
  timestampHeader: string;
}

/** Builds the exact string that gets HMAC-signed — `"<timestamp>.<body>"`. Exported so both `signWebhookRequest` and `verifyWebhookSignature` (and any external receiver reimplementing this scheme) compute it identically. */
export function buildSignedMessage(timestampMs: number, body: string): string {
  return `${timestampMs}.${body}`;
}

/** Signs `body` with `secret` at the given (or current) timestamp — the sender side of the scheme (`WebhookDeliveryService`). */
export function signWebhookRequest(
  secret: string,
  body: string,
  timestampMs: number = Date.now(),
): SignedWebhookRequest {
  const signature = createHmac('sha256', secret)
    .update(buildSignedMessage(timestampMs, body))
    .digest('hex');
  return {
    signatureHeader: `sha256=${signature}`,
    timestampHeader: String(timestampMs),
  };
}

/**
 * The receiver side of the scheme — provided for this repo's own test
 * receivers and as the canonical reference implementation docs/security.md
 * points at. Two independent checks, both required:
 *
 *   1. **Replay window**: `|now - timestampMs| <= toleranceMs`. Checked
 *      *before* the signature (cheaper, and a stale timestamp is rejected
 *      the same way regardless of whether the signature would have
 *      verified) but the signature check is still mandatory even for
 *      recent timestamps -- a fresh timestamp with no valid signature is
 *      just as invalid as a valid signature with a stale timestamp.
 *   2. **Signature**: recomputes the HMAC from `secret`+`body`+the
 *      *claimed* timestamp and compares in constant time
 *      (`timingSafeEqual`) -- never a plain `===` string comparison, which
 *      would leak timing information about how many leading bytes matched.
 */
export function verifyWebhookSignature(
  secret: string,
  body: string,
  signatureHeader: string,
  timestampHeader: string,
  toleranceMs: number,
  now: number = Date.now(),
): boolean {
  const timestampMs = Number(timestampHeader);
  if (!Number.isFinite(timestampMs)) return false;
  if (Math.abs(now - timestampMs) > toleranceMs) return false;

  const expected = signWebhookRequest(
    secret,
    body,
    timestampMs,
  ).signatureHeader;
  const expectedBuffer = Buffer.from(expected);
  const actualBuffer = Buffer.from(signatureHeader);
  if (expectedBuffer.length !== actualBuffer.length) return false;
  return timingSafeEqual(expectedBuffer, actualBuffer);
}

export const WEBHOOK_SIGNATURE_HEADER = 'Manar-Signature';
export const WEBHOOK_TIMESTAMP_HEADER = 'Manar-Timestamp';
export const WEBHOOK_EVENT_TYPE_HEADER = 'Manar-Event-Type';
export const WEBHOOK_DELIVERY_ID_HEADER = 'Manar-Delivery-Id';
