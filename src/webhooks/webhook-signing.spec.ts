import { describe, expect, it } from 'vitest';
import { signWebhookRequest, verifyWebhookSignature } from './webhook-signing';

describe('webhook signing scheme', () => {
  it('a signature signed with the right secret verifies', () => {
    const now = Date.now();
    const { signatureHeader, timestampHeader } = signWebhookRequest(
      'secret-1',
      '{"hello":"world"}',
      now,
    );
    expect(
      verifyWebhookSignature(
        'secret-1',
        '{"hello":"world"}',
        signatureHeader,
        timestampHeader,
        5 * 60 * 1000,
        now,
      ),
    ).toBe(true);
  });

  it('rejects a signature computed with the wrong secret', () => {
    const now = Date.now();
    const { signatureHeader, timestampHeader } = signWebhookRequest(
      'secret-1',
      'body',
      now,
    );
    expect(
      verifyWebhookSignature(
        'wrong-secret',
        'body',
        signatureHeader,
        timestampHeader,
        5 * 60 * 1000,
        now,
      ),
    ).toBe(false);
  });

  it('rejects a tampered body', () => {
    const now = Date.now();
    const { signatureHeader, timestampHeader } = signWebhookRequest(
      'secret-1',
      'original body',
      now,
    );
    expect(
      verifyWebhookSignature(
        'secret-1',
        'tampered body',
        signatureHeader,
        timestampHeader,
        5 * 60 * 1000,
        now,
      ),
    ).toBe(false);
  });

  it('rejects a timestamp outside the replay-protection window, even with a validly recomputed signature for that (stale) timestamp', () => {
    const staleTimestamp = Date.now() - 10 * 60 * 1000; // 10 minutes ago
    const { signatureHeader, timestampHeader } = signWebhookRequest(
      'secret-1',
      'body',
      staleTimestamp,
    );
    expect(
      verifyWebhookSignature(
        'secret-1',
        'body',
        signatureHeader,
        timestampHeader,
        5 * 60 * 1000, // 5 minute tolerance
        Date.now(),
      ),
    ).toBe(false);
  });

  it('accepts a timestamp just inside the tolerance window', () => {
    const now = Date.now();
    const withinWindow = now - 4 * 60 * 1000; // 4 minutes ago
    const { signatureHeader, timestampHeader } = signWebhookRequest(
      'secret-1',
      'body',
      withinWindow,
    );
    expect(
      verifyWebhookSignature(
        'secret-1',
        'body',
        signatureHeader,
        timestampHeader,
        5 * 60 * 1000,
        now,
      ),
    ).toBe(true);
  });

  it('rejects a replayed request: capturing a real signed payload and resending it later (past the tolerance window) fails, even though the signature itself is genuine', () => {
    const originalTimestamp = Date.now();
    const captured = signWebhookRequest('secret-1', 'body', originalTimestamp);
    // An attacker resends the *exact same* captured signature+timestamp
    // long after the original delivery.
    const muchLater = originalTimestamp + 60 * 60 * 1000; // 1 hour later
    expect(
      verifyWebhookSignature(
        'secret-1',
        'body',
        captured.signatureHeader,
        captured.timestampHeader,
        5 * 60 * 1000,
        muchLater,
      ),
    ).toBe(false);
  });

  it('rejects a malformed (non-numeric) timestamp header', () => {
    expect(
      verifyWebhookSignature(
        'secret-1',
        'body',
        'sha256=deadbeef',
        'not-a-number',
        5 * 60 * 1000,
      ),
    ).toBe(false);
  });
});
