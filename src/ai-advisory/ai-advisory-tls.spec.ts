import { describe, expect, it } from 'vitest';
import {
  aiAdvisoryTlsEnabled,
  assertAiAdvisoryTlsMaterial,
} from './ai-advisory.config';

/**
 * Release 2026-11-11 — the manar-ai mTLS switch.
 *
 * Two failure modes are worth pinning, and neither is about TLS mechanics:
 *
 *  1. **The flag inverting.** `z.coerce.boolean()` would have run
 *     JavaScript's `Boolean(...)`, under which the string `"false"` is
 *     `true`. Someone writing `AI_ADVISORY_TLS_ENABLED=false` in a `.env`
 *     file would have silently enabled the thing they were switching off.
 *     A security control that inverts when you write the obvious thing is
 *     worse than no control.
 *  2. **Half-configuration passing startup.** A client with the flag on
 *     but no certificate fails at connect time, which the circuit breaker
 *     reports as "AI advisory unavailable" — correct fail-secure behaviour,
 *     useless diagnostic. It has to fail at startup, naming the variable.
 */

describe('aiAdvisoryTlsEnabled', () => {
  it('treats the string "false" as off', () => {
    expect(aiAdvisoryTlsEnabled({ AI_ADVISORY_TLS_ENABLED: 'false' })).toBe(
      false,
    );
  });

  it('treats the string "true" as on', () => {
    expect(aiAdvisoryTlsEnabled({ AI_ADVISORY_TLS_ENABLED: 'true' })).toBe(
      true,
    );
  });
});

describe('assertAiAdvisoryTlsMaterial', () => {
  it('accepts the disabled case with no certificate material at all', () => {
    // The developer stack: manar-ai still binds plaintext under
    // local/development/test, so this must stay a working configuration.
    expect(() =>
      assertAiAdvisoryTlsMaterial({ AI_ADVISORY_TLS_ENABLED: 'false' }),
    ).not.toThrow();
  });

  it('accepts the enabled case when all three files are configured', () => {
    expect(() =>
      assertAiAdvisoryTlsMaterial({
        AI_ADVISORY_TLS_ENABLED: 'true',
        AI_ADVISORY_TLS_CA_FILE: '/etc/manar/tls/ca.crt',
        AI_ADVISORY_TLS_CERT_FILE: '/etc/manar/tls/tls.crt',
        AI_ADVISORY_TLS_KEY_FILE: '/etc/manar/tls/tls.key',
      }),
    ).not.toThrow();
  });

  it.each([
    ['AI_ADVISORY_TLS_CA_FILE'],
    ['AI_ADVISORY_TLS_CERT_FILE'],
    ['AI_ADVISORY_TLS_KEY_FILE'],
  ])('refuses to start when %s is missing, and names it', (missingKey) => {
    const config: Record<string, string> = {
      AI_ADVISORY_TLS_ENABLED: 'true',
      AI_ADVISORY_TLS_CA_FILE: '/etc/manar/tls/ca.crt',
      AI_ADVISORY_TLS_CERT_FILE: '/etc/manar/tls/tls.crt',
      AI_ADVISORY_TLS_KEY_FILE: '/etc/manar/tls/tls.key',
    };
    delete config[missingKey];

    expect(() =>
      assertAiAdvisoryTlsMaterial(
        config as unknown as Parameters<typeof assertAiAdvisoryTlsMaterial>[0],
      ),
    ).toThrow(missingKey);
  });

  it('treats an empty string as missing, not as a configured path', () => {
    // An unset Helm value renders as an empty string rather than being
    // absent, so this is the shape a real misconfiguration takes.
    expect(() =>
      assertAiAdvisoryTlsMaterial({
        AI_ADVISORY_TLS_ENABLED: 'true',
        AI_ADVISORY_TLS_CA_FILE: '',
        AI_ADVISORY_TLS_CERT_FILE: '/etc/manar/tls/tls.crt',
        AI_ADVISORY_TLS_KEY_FILE: '/etc/manar/tls/tls.key',
      }),
    ).toThrow('AI_ADVISORY_TLS_CA_FILE');
  });

  it('names every missing file at once rather than one per restart', () => {
    let message = '';
    try {
      assertAiAdvisoryTlsMaterial({ AI_ADVISORY_TLS_ENABLED: 'true' });
    } catch (error) {
      message = (error as Error).message;
    }

    expect(message).toContain('AI_ADVISORY_TLS_CA_FILE');
    expect(message).toContain('AI_ADVISORY_TLS_CERT_FILE');
    expect(message).toContain('AI_ADVISORY_TLS_KEY_FILE');
  });
});
