import { describe, expect, it } from 'vitest';
import { applyDlpFloor } from './llm-dlp-floor';

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
