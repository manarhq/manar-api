import { describe, expect, it } from 'vitest';
import {
  advisoryBlocks,
  applyDlpFloor,
  dlpScanText,
} from './dlp-classification';

const blocks: Array<[string, string]> = [
  [
    'jwt',
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
