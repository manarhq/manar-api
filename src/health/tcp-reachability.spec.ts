import { describe, expect, it } from 'vitest';
import { parseTcpEndpoint } from './tcp-reachability';

describe('parseTcpEndpoint', () => {
  it.each([
    ['https://auth-manar.vax.sh', { host: 'auth-manar.vax.sh', port: 443 }],
    ['http://keycloak', { host: 'keycloak', port: 80 }],
    ['http://openfga:8080', { host: 'openfga', port: 8080 }],
    ['temporal:7233', { host: 'temporal', port: 7233 }],
    ['kafka-0:9092,kafka-1:9092', { host: 'kafka-0', port: 9092 }],
  ])('%s', (raw, want) => {
    expect(parseTcpEndpoint(raw)).toEqual(want);
  });
  it('returns null for a bare host with no port or scheme default', () => {
    expect(parseTcpEndpoint('temporal')).toBeNull();
    expect(parseTcpEndpoint('redis://redis')).toBeNull();
  });
});
