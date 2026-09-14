import { describe, expect, it } from 'vitest';
import {
  REDACTED_PLACEHOLDER,
  isCredentialKey,
  redactApprovalParameters,
} from './approval-parameter-redaction';

/**
 * Release 2026-11-11 (brief §3.4). The property under test is *not*
 * "secrets are removed" — this function makes no such claim and its doc
 * comment says so explicitly. The property is: **an approver sees the
 * shape of the action they are binding a grant to, and is told when
 * something was withheld.**
 *
 * The last block pins the documented limitation deliberately, so nobody
 * later reads this module as a DLP guarantee.
 */

describe('isCredentialKey', () => {
  it('matches credential-shaped keys across the usual spellings', () => {
    for (const key of [
      'password',
      'passwd',
      'apiKey',
      'api_key',
      'API-KEY',
      'apikey',
      'accessKey',
      'privateKey',
      'clientSecret',
      'authToken',
      'authorization',
      'sessionId',
      'x-credential',
    ]) {
      expect(isCredentialKey(key), key).toBe(true);
    }
  });

  it('leaves ordinary operational parameters alone', () => {
    for (const key of [
      'resource',
      'hostname',
      'scope',
      'cascade',
      'reason',
      'durationMinutes',
      'userId',
      'severity',
    ]) {
      expect(isCredentialKey(key), key).toBe(false);
    }
  });
});

describe('redactApprovalParameters', () => {
  it('preserves the parameters that change what an action does', () => {
    // The motivating case: an approver reviewing iam/disable-user on
    // user-7 must be able to see `cascade: true` and
    // `scope: "all-sessions"`, because those are what make the action
    // bigger than it looks.
    const result = redactApprovalParameters({
      scope: 'all-sessions',
      cascade: true,
      durationMinutes: 30,
    });

    expect(result.params).toEqual({
      scope: 'all-sessions',
      cascade: true,
      durationMinutes: 30,
    });
    expect(result.redactedKeyPaths).toEqual([]);
    expect(result.truncated).toBe(false);
  });

  it('withholds credential-shaped values but keeps the structure visible', () => {
    const result = redactApprovalParameters({
      host: 'ws-042',
      apiKey: 'sk-live-abcdef',
      nested: { password: 'hunter2', retries: 3 },
    });

    expect(result.params).toEqual({
      host: 'ws-042',
      apiKey: REDACTED_PLACEHOLDER,
      nested: { password: REDACTED_PLACEHOLDER, retries: 3 },
    });
  });

  it('names every withheld location, so a partial object is never read as a complete one', () => {
    const result = redactApprovalParameters({
      apiKey: 'x',
      nested: { password: 'y' },
      items: [{ token: 'z' }, { name: 'ok' }],
    });

    expect(result.redactedKeyPaths).toEqual([
      'apiKey',
      'nested.password',
      'items.0.token',
    ]);
  });

  it('withholds an object under a credential key rather than descending into it', () => {
    const result = redactApprovalParameters({
      credentials: { username: 'svc', password: 'hunter2' },
    });

    expect(result.params).toEqual({ credentials: REDACTED_PLACEHOLDER });
    // One path, not two — the whole subtree was withheld.
    expect(result.redactedKeyPaths).toEqual(['credentials']);
  });

  it('handles scalars, null and arrays at the top level', () => {
    expect(redactApprovalParameters(null).params).toBeNull();
    expect(redactApprovalParameters('plain').params).toBe('plain');
    expect(redactApprovalParameters(42).params).toBe(42);
    expect(redactApprovalParameters([1, 2]).params).toEqual([1, 2]);
  });

  it('reports truncation rather than silently pruning a deep structure', () => {
    // A reviewer looking at a silently-pruned object would believe they
    // had seen all of it.
    let deep: Record<string, unknown> = { leaf: true };
    for (let i = 0; i < 30; i += 1) {
      deep = { nested: deep };
    }

    const result = redactApprovalParameters(deep);

    expect(result.truncated).toBe(true);
  });

  it('bounds a very wide structure', () => {
    const wide: Record<string, unknown> = {};
    for (let i = 0; i < 5_000; i += 1) {
      wide[`key${i}`] = i;
    }

    const result = redactApprovalParameters(wide);

    expect(result.truncated).toBe(true);
  });

  describe('documented limitation — this is not content-based DLP', () => {
    it('does NOT redact a secret placed under an innocuous key', () => {
      // Pinned deliberately. This function is key-name based; content
      // detection is manar-ai's job and this codebase refuses to
      // implement DLP pattern matching in two places. If someone later
      // makes this test fail by adding content matching, they should also
      // revisit the module's doc comment and the note in
      // docs/release/2026-11-11/BLOCKERS.md.
      const result = redactApprovalParameters({
        note: 'the root password is hunter2',
      });

      expect(result.params).toEqual({
        note: 'the root password is hunter2',
      });
      expect(result.redactedKeyPaths).toEqual([]);
    });
  });
});
