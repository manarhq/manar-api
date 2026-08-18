import { beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../app';
import type { EdrHost } from '../types';

const API_KEY = 'test-api-key';
const AUTH_HEADER = { authorization: `Bearer ${API_KEY}` };

describe('EDR endpoints', () => {
  let app: FastifyInstance;

  beforeEach(() => {
    app = buildApp({ apiKey: API_KEY, logger: false });
  });

  it('GET /v1/edr/hosts/:id returns seeded WS-042, not isolated, with a suspicious process', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/edr/hosts/WS-042',
      headers: AUTH_HEADER,
    });

    expect(res.statusCode).toBe(200);
    const body = res.json<EdrHost>();
    expect(body.id).toBe('WS-042');
    expect(body.isolated).toBe(false);
    expect(
      body.processes.some((p) => p.suspicious && p.status === 'running'),
    ).toBe(true);
  });

  it('GET /v1/edr/hosts/:id 404s for an unknown host', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/edr/hosts/NOPE',
      headers: AUTH_HEADER,
    });
    expect(res.statusCode).toBe(404);
  });

  it('isolate-host sets isolated=true, visible on a subsequent GET', async () => {
    const isolateRes = await app.inject({
      method: 'POST',
      url: '/v1/edr/hosts/WS-042/isolate',
      headers: AUTH_HEADER,
    });
    expect(isolateRes.statusCode).toBe(200);
    expect(isolateRes.json<EdrHost>().isolated).toBe(true);

    const getRes = await app.inject({
      method: 'GET',
      url: '/v1/edr/hosts/WS-042',
      headers: AUTH_HEADER,
    });
    expect(getRes.json<EdrHost>().isolated).toBe(true);
  });

  it('release-host sets isolated=false, visible on a subsequent GET', async () => {
    await app.inject({
      method: 'POST',
      url: '/v1/edr/hosts/WS-042/isolate',
      headers: AUTH_HEADER,
    });

    const releaseRes = await app.inject({
      method: 'POST',
      url: '/v1/edr/hosts/WS-042/release',
      headers: AUTH_HEADER,
    });
    expect(releaseRes.statusCode).toBe(200);
    expect(releaseRes.json<EdrHost>().isolated).toBe(false);

    const getRes = await app.inject({
      method: 'GET',
      url: '/v1/edr/hosts/WS-042',
      headers: AUTH_HEADER,
    });
    expect(getRes.json<EdrHost>().isolated).toBe(false);
  });

  it('isolate/release 404 for an unknown host', async () => {
    const isolateRes = await app.inject({
      method: 'POST',
      url: '/v1/edr/hosts/NOPE/isolate',
      headers: AUTH_HEADER,
    });
    expect(isolateRes.statusCode).toBe(404);

    const releaseRes = await app.inject({
      method: 'POST',
      url: '/v1/edr/hosts/NOPE/release',
      headers: AUTH_HEADER,
    });
    expect(releaseRes.statusCode).toBe(404);
  });

  it('terminate-process flags the process terminated, visible on a subsequent GET', async () => {
    const terminateRes = await app.inject({
      method: 'POST',
      url: '/v1/edr/hosts/WS-042/processes/4521/terminate',
      headers: AUTH_HEADER,
    });
    expect(terminateRes.statusCode).toBe(200);
    const terminated = terminateRes
      .json<EdrHost>()
      .processes.find((p) => p.pid === 4521);
    expect(terminated?.status).toBe('terminated');

    const getRes = await app.inject({
      method: 'GET',
      url: '/v1/edr/hosts/WS-042',
      headers: AUTH_HEADER,
    });
    const afterGet = getRes
      .json<EdrHost>()
      .processes.find((p) => p.pid === 4521);
    expect(afterGet?.status).toBe('terminated');
  });

  it('terminate-process 404s for an unknown host', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/edr/hosts/NOPE/processes/4521/terminate',
      headers: AUTH_HEADER,
    });
    expect(res.statusCode).toBe(404);
  });

  it('terminate-process 404s for an unknown pid on a known host', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/edr/hosts/WS-042/processes/99999/terminate',
      headers: AUTH_HEADER,
    });
    expect(res.statusCode).toBe(404);
  });
});
