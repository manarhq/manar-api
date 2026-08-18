import { beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../app';
import type { IamUser } from '../types';

const API_KEY = 'test-api-key';
const AUTH_HEADER = { authorization: `Bearer ${API_KEY}` };

describe('IAM endpoints', () => {
  let app: FastifyInstance;

  beforeEach(() => {
    app = buildApp({ apiKey: API_KEY, logger: false });
  });

  it('GET /v1/iam/users/:id returns the seeded demo user, enabled', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/iam/users/jdoe',
      headers: AUTH_HEADER,
    });

    expect(res.statusCode).toBe(200);
    expect(res.json<IamUser>()).toMatchObject({ id: 'jdoe', enabled: true });
  });

  it('GET /v1/iam/users/:id 404s for an unknown user', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/iam/users/NOPE',
      headers: AUTH_HEADER,
    });
    expect(res.statusCode).toBe(404);
  });

  it('disable-user sets enabled=false, visible on a subsequent GET', async () => {
    const disableRes = await app.inject({
      method: 'POST',
      url: '/v1/iam/users/jdoe/disable',
      headers: AUTH_HEADER,
    });
    expect(disableRes.statusCode).toBe(200);
    expect(disableRes.json<IamUser>().enabled).toBe(false);

    const getRes = await app.inject({
      method: 'GET',
      url: '/v1/iam/users/jdoe',
      headers: AUTH_HEADER,
    });
    expect(getRes.json<IamUser>().enabled).toBe(false);
  });

  it('disable-user 404s for an unknown user', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/iam/users/NOPE/disable',
      headers: AUTH_HEADER,
    });
    expect(res.statusCode).toBe(404);
  });
});
