import { beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../app';
import type { EdrHost, IamUser, IpLookupResult } from '../types';

const API_KEY = 'test-api-key';
const AUTH_HEADER = { authorization: `Bearer ${API_KEY}` };

describe('POST /_demo/reset', () => {
  let app: FastifyInstance;

  beforeEach(() => {
    app = buildApp({ apiKey: API_KEY, logger: false });
  });

  it('requires no auth and reports reset', async () => {
    const res = await app.inject({ method: 'POST', url: '/_demo/reset' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'reset' });
  });

  it('restores an isolated host to isolated=false', async () => {
    await app.inject({
      method: 'POST',
      url: '/v1/edr/hosts/WS-042/isolate',
      headers: AUTH_HEADER,
    });

    let getRes = await app.inject({
      method: 'GET',
      url: '/v1/edr/hosts/WS-042',
      headers: AUTH_HEADER,
    });
    expect(getRes.json<EdrHost>().isolated).toBe(true);

    await app.inject({ method: 'POST', url: '/_demo/reset' });

    getRes = await app.inject({
      method: 'GET',
      url: '/v1/edr/hosts/WS-042',
      headers: AUTH_HEADER,
    });
    expect(getRes.json<EdrHost>().isolated).toBe(false);
  });

  it('restores a disabled user to enabled=true', async () => {
    await app.inject({
      method: 'POST',
      url: '/v1/iam/users/jdoe/disable',
      headers: AUTH_HEADER,
    });
    await app.inject({ method: 'POST', url: '/_demo/reset' });

    const getRes = await app.inject({
      method: 'GET',
      url: '/v1/iam/users/jdoe',
      headers: AUTH_HEADER,
    });
    expect(getRes.json<IamUser>().enabled).toBe(true);
  });

  it('clears the firewall blocklist', async () => {
    await app.inject({
      method: 'POST',
      url: '/v1/firewall/block',
      headers: AUTH_HEADER,
      payload: { ip: '203.0.113.77' },
    });
    await app.inject({ method: 'POST', url: '/_demo/reset' });

    const lookupRes = await app.inject({
      method: 'GET',
      url: '/v1/firewall/lookup?ip=203.0.113.77',
      headers: AUTH_HEADER,
    });
    expect(lookupRes.json<IpLookupResult>().blocked).toBe(false);
  });

  it('restores a terminated process to running', async () => {
    await app.inject({
      method: 'POST',
      url: '/v1/edr/hosts/WS-042/processes/4521/terminate',
      headers: AUTH_HEADER,
    });
    await app.inject({ method: 'POST', url: '/_demo/reset' });

    const getRes = await app.inject({
      method: 'GET',
      url: '/v1/edr/hosts/WS-042',
      headers: AUTH_HEADER,
    });
    const process = getRes
      .json<EdrHost>()
      .processes.find((p) => p.pid === 4521);
    expect(process?.status).toBe('running');
  });
});
