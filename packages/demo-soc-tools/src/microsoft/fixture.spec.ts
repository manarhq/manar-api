import { beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../app';
import { DEFENDER_SCOPE, FIXTURE_DEFAULTS, GRAPH_SCOPE } from './fixture';
import { FIXTURE_MACHINE_ID, FIXTURE_USER_ID } from './seed-data';

async function token(app: FastifyInstance, scope: string): Promise<string> {
  const res = await app.inject({
    method: 'POST',
    url: `/microsoft/login/${FIXTURE_DEFAULTS.tenantId}/oauth2/v2.0/token`,
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: FIXTURE_DEFAULTS.clientId,
      client_secret: FIXTURE_DEFAULTS.clientSecret,
      scope,
    }).toString(),
  });
  expect(res.statusCode).toBe(200);
  return res.json<{ access_token: string }>().access_token;
}

describe('Microsoft DEMO FIXTURE', () => {
  let app: FastifyInstance;

  beforeEach(() => {
    app = buildApp({ apiKey: 'k', logger: false });
  });

  it('rejects a wrong client secret', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/microsoft/login/${FIXTURE_DEFAULTS.tenantId}/oauth2/v2.0/token`,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: `grant_type=client_credentials&client_id=${FIXTURE_DEFAULTS.clientId}&client_secret=wrong&scope=${encodeURIComponent(GRAPH_SCOPE)}`,
    });
    expect(res.statusCode).toBe(401);
  });

  it('refuses a Graph token on Defender routes', async () => {
    const graph = await token(app, GRAPH_SCOPE);
    const res = await app.inject({
      method: 'GET',
      url: `/microsoft/defender/api/machines/${FIXTURE_MACHINE_ID}`,
      headers: { authorization: `Bearer ${graph}` },
    });
    expect(res.statusCode).toBe(401);
  });

  it('keeps isolate and disable consistent with later reads, labelled as fixture data', async () => {
    const defender = await token(app, DEFENDER_SCOPE);
    const isolate = await app.inject({
      method: 'POST',
      url: `/microsoft/defender/api/machines/${FIXTURE_MACHINE_ID}/isolate`,
      headers: { authorization: `Bearer ${defender}` },
      payload: { Comment: 'test', IsolationType: 'Full' },
    });
    expect(isolate.statusCode).toBe(201);
    expect(isolate.json()).toMatchObject({
      type: 'Isolate',
      _dataOrigin: 'DEMO_FIXTURE',
    });
    const actions = await app.inject({
      method: 'GET',
      url: `/microsoft/defender/api/machineactions?$filter=${encodeURIComponent(`machineId eq '${FIXTURE_MACHINE_ID}'`)}`,
      headers: { authorization: `Bearer ${defender}` },
    });
    expect(actions.json()).toMatchObject({
      value: [{ type: 'Isolate', status: 'Succeeded' }],
    });

    const graph = await token(app, GRAPH_SCOPE);
    const patch = await app.inject({
      method: 'PATCH',
      url: `/microsoft/graph/v1.0/users/${FIXTURE_USER_ID}`,
      headers: { authorization: `Bearer ${graph}` },
      payload: { accountEnabled: false },
    });
    expect(patch.statusCode).toBe(204);
    const user = await app.inject({
      method: 'GET',
      url: `/microsoft/graph/v1.0/users/${FIXTURE_USER_ID}`,
      headers: { authorization: `Bearer ${graph}` },
    });
    expect(user.json()).toMatchObject({ accountEnabled: false });
  });
});
