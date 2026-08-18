import { beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../app';
import type { FirewallBlockResult, IpLookupResult } from '../types';

const API_KEY = 'test-api-key';
const AUTH_HEADER = { authorization: `Bearer ${API_KEY}` };

describe('Firewall endpoints', () => {
  let app: FastifyInstance;

  beforeEach(() => {
    app = buildApp({ apiKey: API_KEY, logger: false });
  });

  it('GET /v1/firewall/lookup returns malicious reputation for the seeded suspicious IP', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/firewall/lookup?ip=203.0.113.77',
      headers: AUTH_HEADER,
    });

    expect(res.statusCode).toBe(200);
    expect(res.json<IpLookupResult>()).toMatchObject({
      ip: '203.0.113.77',
      reputation: 'malicious',
      blocked: false,
    });
  });

  it('GET /v1/firewall/lookup returns unknown reputation for an unseeded IP', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/firewall/lookup?ip=198.51.100.9',
      headers: AUTH_HEADER,
    });

    expect(res.statusCode).toBe(200);
    expect(res.json<IpLookupResult>()).toMatchObject({
      ip: '198.51.100.9',
      reputation: 'unknown',
      blocked: false,
    });
  });

  it('GET /v1/firewall/lookup 400s with no ip query param', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/firewall/lookup',
      headers: AUTH_HEADER,
    });
    expect(res.statusCode).toBe(400);
  });

  it('block-ip adds to the blocklist, visible on a subsequent lookup', async () => {
    const blockRes = await app.inject({
      method: 'POST',
      url: '/v1/firewall/block',
      headers: AUTH_HEADER,
      payload: { ip: '203.0.113.77' },
    });
    expect(blockRes.statusCode).toBe(200);
    expect(blockRes.json<FirewallBlockResult>()).toMatchObject({
      ip: '203.0.113.77',
      blocked: true,
    });
    expect(blockRes.json<FirewallBlockResult>().blocklist).toContain(
      '203.0.113.77',
    );

    const lookupRes = await app.inject({
      method: 'GET',
      url: '/v1/firewall/lookup?ip=203.0.113.77',
      headers: AUTH_HEADER,
    });
    expect(lookupRes.json<IpLookupResult>().blocked).toBe(true);
  });

  it('unblock-ip removes from the blocklist, visible on a subsequent lookup', async () => {
    await app.inject({
      method: 'POST',
      url: '/v1/firewall/block',
      headers: AUTH_HEADER,
      payload: { ip: '203.0.113.77' },
    });

    const unblockRes = await app.inject({
      method: 'POST',
      url: '/v1/firewall/unblock',
      headers: AUTH_HEADER,
      payload: { ip: '203.0.113.77' },
    });
    expect(unblockRes.statusCode).toBe(200);
    expect(unblockRes.json<FirewallBlockResult>().blocked).toBe(false);
    expect(unblockRes.json<FirewallBlockResult>().blocklist).not.toContain(
      '203.0.113.77',
    );

    const lookupRes = await app.inject({
      method: 'GET',
      url: '/v1/firewall/lookup?ip=203.0.113.77',
      headers: AUTH_HEADER,
    });
    expect(lookupRes.json<IpLookupResult>().blocked).toBe(false);
  });

  it('block-ip 400s with no ip in the body', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/firewall/block',
      headers: AUTH_HEADER,
      payload: {},
    });
    expect(res.statusCode).toBe(400);
  });
});
