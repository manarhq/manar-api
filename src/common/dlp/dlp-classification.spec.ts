import { describe, expect, it, vi } from 'vitest';
import type { DlpAdvisory } from '../../ai-advisory/ai-advisory-client.service';
import {
  DLP_LOCATE_MAX_CALLS,
  advisoryBlocks,
  applyDlpFloor,
  classifyDlp,
  dlpScanText,
} from './dlp-classification';

const blocks: Array<[string, string]> = [
  [
    'jwt',
    // nosemgrep: generic.secrets.security.detected-jwt-token.detected-jwt-token (synthetic DLP fixture, signature is "signature-value")
    'token eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.c2lnbmF0dXJlLXZhbHVl',
  ],
  [
    'bearer_token',
    'Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789',
  ],
  ['private_key', '-----BEGIN RSA PRIVATE KEY-----\nMIIE...'],
  ['private_key', '-----BEGIN PRIVATE KEY-----'],
  [
    'azure_connection_string',
    'DefaultEndpointsProtocol=https;AccountName=x;AccountKey=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA==;',
  ],
  [
    'azure_connection_string',
    'Endpoint=sb://x.servicebus.windows.net/;SharedAccessKeyName=r;SharedAccessKey=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5',
  ],
  [
    'azure_sas_token',
    'https://x.blob.core.windows.net/c?sv=2022-11-02&sig=AbCdEfGh1234567890%2BxYz%3D',
  ],
  ['json_secret_value', '{"client_secret": "s3cr3t-value"}'],
  ['json_secret_value', '{"password":"hunter22"}'],
  [
    'entra_client_secret',
    'secret is Abc8Q~0123456789abcdefghijklmnopqrstuvwx ok',
  ],
];

describe('applyDlpFloor', () => {
  it.each(blocks)('flags %s', (type, text) => {
    expect(
      applyDlpFloor({ messages: [{ content: text }] }).credentialTypes,
    ).toContain(type);
  });

  it('passes ordinary SOC content untouched', () => {
    const input = {
      messages: [
        {
          role: 'tool',
          content:
            '{"id":"4201","user":"alice@contoso.example","device":"fx-ws-042","sha1":"a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"}',
        },
      ],
      tools: [
        {
          function: {
            parameters: { properties: { password: { type: 'string' } } },
          },
        },
      ],
    };
    const result = applyDlpFloor(input);
    expect(result.credentialTypes).toEqual([]);
    expect(result.piiTypes).toEqual([]);
    expect(result.value).toEqual(input);
  });

  it('redacts Emirates ID and UAE IBAN in nested strings without mutating the input', () => {
    const input = {
      messages: [
        {
          content: [
            {
              type: 'text',
              text: 'EID 784199012345671 IBAN AE07 0331 2345 6789 0123 456',
            },
          ],
        },
      ],
    };
    const result = applyDlpFloor(input);
    expect(result.piiTypes).toEqual(['emirates_id', 'uae_iban']);
    expect(JSON.stringify(result.value)).toBe(
      JSON.stringify({
        messages: [
          {
            content: [
              {
                type: 'text',
                text: 'EID [REDACTED:EMIRATES_ID] IBAN [REDACTED:UAE_IBAN]',
              },
            ],
          },
        ],
      }),
    );
    expect(input.messages[0]?.content[0]?.text).toContain('784199012345671');
  });
});

describe('shared DLP classification (result DLP, 25 Sep decision)', () => {
  it.each([
    [
      'payment_card',
      'card 4111 1111 1111 1111 exp 12/29',
      'card [REDACTED:PAYMENT_CARD] exp 12/29',
    ],
    ['payment_card', 'pan 5555555555554444.', 'pan [REDACTED:PAYMENT_CARD].'],
    [
      'uae_mobile',
      'call +971 50 123 4567 now',
      'call [REDACTED:UAE_MOBILE] now',
    ],
    ['uae_mobile', 'tel 0551234567', 'tel [REDACTED:UAE_MOBILE]'],
    ['uae_mobile', 'tel 00971-56-765-4321', 'tel [REDACTED:UAE_MOBILE]'],
  ])('redacts %s in place', (type, text, expected) => {
    const result = applyDlpFloor({ note: text });
    expect(result.piiTypes).toEqual([type]);
    expect(result.credentialTypes).toEqual([]);
    expect(result.value).toEqual({ note: expected });
    expect(result.counts).toEqual({ [type]: 1 });
  });

  it.each([
    ['a Luhn-invalid 16-digit number', '4111 1111 1111 1112'],
    ['an epoch-ms timestamp', '1727280000000'],
    ['a Defender machine id', '4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70'],
    ['an IPv4 address', '203.0.113.77'],
    ['a non-UAE phone', '+44 20 7946 0958'],
  ])('leaves %s alone', (_label, text) => {
    const result = applyDlpFloor({ v: text });
    expect(result.piiTypes).toEqual([]);
    expect(result.value).toEqual({ v: text });
  });

  it('passes e-mail addresses / UPNs through unchanged', () => {
    const input = {
      userPrincipalName: 'adele.vance@fixture.example',
      mail: 'Adele.Vance@contoso.onmicrosoft.com',
    };
    const result = applyDlpFloor(input);
    expect(result).toEqual({
      value: input,
      credentialTypes: [],
      piiTypes: [],
      counts: {},
    });
  });

  it('walks nested objects and arrays, counts every match, and keeps everything else', () => {
    const input = {
      incident: {
        id: 4201,
        assignedTo: 'soc@contoso.example',
        alerts: [
          { evidence: [{ user: 'EID 784-1990-1234567-1', ok: true }] },
          { evidence: [{ note: 'EID 784199012345671 or 784199012345671' }] },
        ],
      },
    };
    const result = applyDlpFloor(input);
    expect(result.counts).toEqual({ emirates_id: 3 });
    expect(result.value.incident.id).toBe(4201);
    expect(result.value.incident.assignedTo).toBe('soc@contoso.example');
    expect(result.value.incident.alerts[0]!.evidence[0]).toEqual({
      user: 'EID [REDACTED:EMIRATES_ID]',
      ok: true,
    });
    expect(JSON.stringify(result.value)).not.toContain('784');
  });

  it('flags a credential nested deep in an array', () => {
    const result = applyDlpFloor({
      value: [{ a: [{ b: '-----BEGIN PRIVATE KEY-----' }] }],
    });
    expect(result.credentialTypes).toEqual(['private_key']);
    expect(result.counts).toEqual({ private_key: 1 });
  });

  it('treats nesting beyond the depth bound as a credential-class finding (fail closed)', () => {
    let deep: unknown = 'leaf';
    for (let i = 0; i < 100; i++) deep = { n: deep };
    const result = applyDlpFloor(deep);
    expect(result.credentialTypes).toEqual(['scan_depth_exceeded']);
    expect(JSON.stringify(result.value)).not.toContain('leaf');
  });

  it('advisoryBlocks only on credential types, never on e-mail/PII/other or the system marker', () => {
    const f = (type: string, source = 'pattern') => ({
      type,
      source,
      redactedPreview: 'x',
      confidence: 0.9,
    });
    const adv = (...findings: ReturnType<typeof f>[]) => ({
      findings,
      overallSeverity: 'SEVERITY_HIGH',
    });
    expect(
      advisoryBlocks(adv(f('TYPE_EMAIL'), f('TYPE_PII'), f('TYPE_OTHER'))),
    ).toBe(false);
    expect(advisoryBlocks(adv(f('TYPE_API_KEY', 'system')))).toBe(false);
    for (const t of [
      'TYPE_API_KEY',
      'TYPE_PRIVATE_KEY',
      'TYPE_JWT',
      'TYPE_CREDENTIAL',
    ]) {
      expect(advisoryBlocks(adv(f(t)))).toBe(true);
    }
  });

  it('dlpScanText joins every string leaf, keys excluded', () => {
    expect(dlpScanText({ a: 'x', b: [1, 'y', { c: 'z' }], d: null })).toBe(
      'x\ny\nz',
    );
    expect(dlpScanText('plain')).toBe('plain');
  });
});

describe('classifyDlp: manar-ai generic PII located per string leaf', () => {
  const finding = (type: string, source = 'ai') => ({
    type,
    source,
    redactedPreview: 'x',
    confidence: 0.8,
  });
  /** Fake manar-ai: `rule(content)` gives the finding types for that content. */
  const fake = (rule: (content: string) => string[] | null) =>
    vi.fn((content: string) => {
      const types = rule(content);
      return Promise.resolve<DlpAdvisory | null>(
        types && {
          findings: types.map((t) => finding(t)),
          overallSeverity: 'SEVERITY_LOW',
        },
      );
    });
  const piiIf = (needle: string) => (c: string) =>
    c.includes(needle) ? ['TYPE_PII'] : [];

  it('replaces only the flagged leaf among many, within the call bound', async () => {
    const input = {
      upn: 'adele.vance@fixture.example',
      rows: Array.from({ length: 200 }, (_, i) => `row ${i}`),
      owner: { name: 'Fatima Al Mansoori', id: 7 },
    };
    const analyze = fake(piiIf('Fatima'));
    const r = await classifyDlp(input, analyze);
    expect(r.blocked).toBe(false);
    expect(r.value).toEqual({
      ...input,
      owner: { name: '[REDACTED:PII]', id: 7 },
    });
    expect(r.advisoryRedactedCounts).toEqual({ TYPE_PII: 1 });
    expect(analyze.mock.calls.length).toBeLessThanOrEqual(
      1 + DLP_LOCATE_MAX_CALLS,
    );
    expect(input.owner.name).toBe('Fatima Al Mansoori');
  });

  it('uses [REDACTED:OTHER] for TYPE_OTHER and ignores the system marker and e-mail', async () => {
    const analyze = vi.fn((c: string) =>
      Promise.resolve<DlpAdvisory>({
        findings: [
          finding('TYPE_OTHER', 'system'),
          finding('TYPE_EMAIL', 'deterministic'),
          ...(c.includes('N1234567') ? [finding('TYPE_OTHER')] : []),
        ],
        overallSeverity: 'SEVERITY_MEDIUM',
      }),
    );
    const r = await classifyDlp(
      { a: 'passport N1234567', b: 'adele.vance@fixture.example' },
      analyze,
    );
    expect(r.value).toEqual({
      a: '[REDACTED:OTHER]',
      b: 'adele.vance@fixture.example',
    });
  });

  it('blocks when a flagged group does not reproduce in either half', async () => {
    const r = await classifyDlp(
      { a: 'first', b: 'second' },
      fake((c) => (c.includes('\n') ? ['TYPE_PII'] : [])),
    );
    expect(r.blocked).toBe(true);
    expect(r.unlocatedTypes).toEqual(['TYPE_PII']);
  });

  it('blocks when manar-ai becomes unavailable while locating', async () => {
    let n = 0;
    const r = await classifyDlp(
      { a: 'Fatima', b: 'x' },
      fake((c) => (n++ === 0 ? piiIf('Fatima')(c) : null)),
    );
    expect(r.blocked).toBe(true);
    expect(r.unlocatedTypes).toEqual(['TYPE_PII']);
  });

  it('blocks instead of passing when locating needs more calls than the bound', async () => {
    const leaves = Array.from({ length: 64 }, (_, i) => `pii-${i}`);
    const analyze = fake((c) => (c.includes('pii-') ? ['TYPE_PII'] : []));
    const r = await classifyDlp(leaves, analyze);
    expect(r.blocked).toBe(true);
    expect(analyze.mock.calls.length).toBeLessThanOrEqual(
      1 + DLP_LOCATE_MAX_CALLS,
    );
  });

  it('blocks on a credential finding that only shows up in a located half', async () => {
    const r = await classifyDlp(
      { a: 'Fatima', b: 'k' },
      fake((c) => (c === 'k' ? ['TYPE_API_KEY'] : piiIf('Fatima')(c))),
    );
    expect(r.blocked).toBe(true);
    expect(r.blockingFindings.map((f) => f.type)).toEqual(['TYPE_API_KEY']);
  });

  it('returns manar-ai null to the caller and skips manar-ai after a floor credential', async () => {
    const down = await classifyDlp(
      { a: 'x' },
      fake(() => null),
    );
    expect(down.advisory).toBeNull();
    expect(down.blocked).toBe(false);
    const analyze = fake(() => []);
    const cred = await classifyDlp(
      { a: '-----BEGIN PRIVATE KEY-----' },
      analyze,
    );
    expect(cred.blocked).toBe(true);
    expect(analyze).not.toHaveBeenCalled();
  });
});
