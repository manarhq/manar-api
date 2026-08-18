import { beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from './app';

const API_KEY = 'test-api-key';
const AUTH_HEADER = { authorization: `Bearer ${API_KEY}` };

describe('health endpoints', () => {
  let app: FastifyInstance;

  beforeEach(() => {
    app = buildApp({ apiKey: API_KEY, logger: false });
  });

  it('GET /health/live reports ok without auth', async () => {
    const res = await app.inject({ method: 'GET', url: '/health/live' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok' });
  });

  it('GET /health/ready reports ok without auth', async () => {
    const res = await app.inject({ method: 'GET', url: '/health/ready' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok' });
  });
});

describe('bearer auth on /v1/*', () => {
  let app: FastifyInstance;

  const protectedRoutes: { method: 'GET' | 'POST'; url: string }[] = [
    { method: 'GET', url: '/v1/siem/events' },
    { method: 'GET', url: '/v1/siem/incidents/INC-2026-0042' },
    { method: 'GET', url: '/v1/edr/hosts/WS-042' },
    { method: 'POST', url: '/v1/edr/hosts/WS-042/isolate' },
    { method: 'POST', url: '/v1/edr/hosts/WS-042/release' },
    { method: 'POST', url: '/v1/edr/hosts/WS-042/processes/4521/terminate' },
    { method: 'GET', url: '/v1/iam/users/jdoe' },
    { method: 'POST', url: '/v1/iam/users/jdoe/disable' },
    { method: 'GET', url: '/v1/firewall/lookup?ip=203.0.113.77' },
    { method: 'POST', url: '/v1/firewall/block' },
    { method: 'POST', url: '/v1/firewall/unblock' },
  ];

  beforeEach(() => {
    app = buildApp({ apiKey: API_KEY, logger: false });
  });

  it.each(protectedRoutes)(
    '401s on $method $url with no Authorization header',
    async ({ method, url }) => {
      const res = await app.inject({ method, url });
      expect(res.statusCode).toBe(401);
      expect(res.json()).toEqual({ error: 'Unauthorized' });
    },
  );

  it.each(protectedRoutes)(
    '401s on $method $url with an invalid token',
    async ({ method, url }) => {
      const res = await app.inject({
        method,
        url,
        headers: { authorization: 'Bearer wrong-token' },
      });
      expect(res.statusCode).toBe(401);
    },
  );

  it('accepts a valid token', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/edr/hosts/WS-042',
      headers: AUTH_HEADER,
    });
    expect(res.statusCode).toBe(200);
  });

  it('does not require auth for /_demo/reset', async () => {
    const res = await app.inject({ method: 'POST', url: '/_demo/reset' });
    expect(res.statusCode).toBe(200);
  });
});
