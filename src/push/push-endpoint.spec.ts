import { describe, expect, it } from 'vitest';
import { isAllowedPushEndpoint } from './push-endpoint';

describe('push endpoint allow-list (SSRF)', () => {
  it('accepts the browsers push services', () => {
    for (const u of [
      'https://fcm.googleapis.com/fcm/send/abc',
      'https://updates.push.services.mozilla.com/wpush/v2/abc',
      'https://wns2-par02p.notify.windows.com/w/?token=x',
      'https://web.push.apple.com/abc',
      'https://api.push.apple.com:443/3/device/x',
    ])
      expect(isAllowedPushEndpoint(u), u).toBe(true);
  });
  it('rejects everything else', () => {
    for (const u of [
      'http://fcm.googleapis.com/x',
      'https://169.254.169.254/latest',
      'https://127.0.0.1/x',
      'https://[::1]/x',
      'https://2130706433/x',
      'https://localhost/x',
      'https://fcm.googleapis.com:8443/x',
      'https://fcm.googleapis.com.evil.example/x',
      'https://evilfcm.googleapis.com/x',
      'https://user:pw@fcm.googleapis.com/x',
      'https://notify.windows.com.evil.test/x',
      'https://push.apple.com/x',
      'not a url',
    ])
      expect(isAllowedPushEndpoint(u), u).toBe(false);
  });
});
