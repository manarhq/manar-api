import { describe, expect, it, vi } from 'vitest';
import { MailerService, acsHeaders, parseAcs } from './mailer.service';

describe('ACS mail signing', () => {
  it('parses the connection string and refuses a non-https endpoint', () => {
    const k = Buffer.from('secret').toString('base64');
    expect(
      parseAcs(`endpoint=https://a.communication.azure.com/;accesskey=${k}`)
        ?.endpoint,
    ).toBe('https://a.communication.azure.com');
    expect(parseAcs(`endpoint=http://a/;accesskey=${k}`)).toBeNull();
    expect(parseAcs('nonsense')).toBeNull();
  });
  it('signs host, date and body hash', () => {
    const h = acsHeaders(
      Buffer.from('k'),
      'a.example',
      '/emails:send?api-version=1',
      '{}',
      new Date(0),
    );
    expect(h['x-ms-date']).toBe('Thu, 01 Jan 1970 00:00:00 GMT');
    expect(h['x-ms-content-sha256']).toBe(
      'RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=',
    );
    expect(h.Authorization).toMatch(
      /^HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature=/,
    );
  });
});

describe('mailer', () => {
  it('refuses the realm placeholder addresses without calling ACS', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const k = Buffer.from('k').toString('base64');
    const m = new MailerService({
      get: () => `endpoint=https://a.communication.azure.com/;accesskey=${k}`,
    } as never);
    expect(
      await m.send({
        to: 'abc@idp.invalid',
        subject: 's',
        text: 't',
        html: 'h',
      }),
    ).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
