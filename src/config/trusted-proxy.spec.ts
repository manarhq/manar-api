import { describe, expect, it } from 'vitest';
import {
  callerAddress,
  httpAdapterOptions,
  parseCidrs,
  trustedProxyIssues,
} from './trusted-proxy';

describe('trusted proxies', () => {
  it('takes addresses and CIDR ranges, refuses anything else', () => {
    expect(parseCidrs('10.42.0.0/16, 127.0.0.1,fd00::/8')).toEqual([
      '10.42.0.0/16',
      '127.0.0.1',
      'fd00::/8',
    ]);
    for (const bad of ['10.0.0.0/33', 'proxy.local', '10.0.0.0/8/1', '*']) {
      expect(parseCidrs(bad)).toBeNull();
    }
  });

  it('turns trustProxy on only when proxies are listed', () => {
    expect(httpAdapterOptions({})).toEqual({});
    expect(
      httpAdapterOptions({ MANAR_TRUSTED_PROXY_CIDRS: '10.42.0.0/16' }),
    ).toEqual({
      trustProxy: ['10.42.0.0/16'],
    });
  });

  it('the public MCP endpoint does not start without the proxies named, or none', () => {
    expect(trustedProxyIssues({ MANAR_MCP_ENABLED: 'true' })).toHaveLength(1);
    expect(
      trustedProxyIssues({
        MANAR_MCP_ENABLED: 'true',
        MANAR_TRUSTED_PROXY_CIDRS: 'none',
      }),
    ).toEqual([]);
    expect(trustedProxyIssues({ MANAR_MCP_ENABLED: 'false' })).toEqual([]);
  });

  it('production does not start without the proxies named, whatever else is on', () => {
    expect(trustedProxyIssues({ NODE_ENV: 'production' })).toHaveLength(1);
    expect(
      trustedProxyIssues({
        NODE_ENV: 'production',
        MANAR_TRUSTED_PROXY_CIDRS: ' ',
      }),
    ).toHaveLength(1);
    expect(
      trustedProxyIssues({
        NODE_ENV: 'production',
        MANAR_TRUSTED_PROXY_CIDRS: '10.42.0.0/16',
      }),
    ).toEqual([]);
    expect(trustedProxyIssues({ NODE_ENV: 'development' })).toEqual([]);
    expect(
      trustedProxyIssues({
        NODE_ENV: 'production',
        MANAR_TRUSTED_PROXY_CIDRS: 'none',
      }),
    ).toEqual([]);
    expect(httpAdapterOptions({ MANAR_TRUSTED_PROXY_CIDRS: 'none' })).toEqual(
      {},
    );
  });
});

describe('callerAddress', () => {
  it('is the request address only when the proxies in front are named', () => {
    expect(
      callerAddress('10.1.2.3', { MANAR_TRUSTED_PROXY_CIDRS: '10.42.0.0/16' }),
    ).toBe('10.1.2.3');
    expect(
      callerAddress('10.1.2.3', { MANAR_TRUSTED_PROXY_CIDRS: 'none' }),
    ).toBe('10.1.2.3');
    // Unset: request.ip may be the proxy pod, so address checks must not pass on it.
    expect(callerAddress('10.1.2.3', {})).toBe('unknown');
    expect(callerAddress('10.1.2.3', { MANAR_TRUSTED_PROXY_CIDRS: ' ' })).toBe(
      'unknown',
    );
  });
});
