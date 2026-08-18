import { beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../app';
import type { Incident, SiemEvent } from '../types';

const API_KEY = 'test-api-key';
const AUTH_HEADER = { authorization: `Bearer ${API_KEY}` };

interface EventsResponse {
  events: SiemEvent[];
}

describe('SIEM endpoints', () => {
  let app: FastifyInstance;

  beforeEach(() => {
    app = buildApp({ apiKey: API_KEY, logger: false });
  });

  it('GET /v1/siem/events returns all seeded events with no query', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/siem/events',
      headers: AUTH_HEADER,
    });

    expect(res.statusCode).toBe(200);
    const body = res.json<EventsResponse>();
    expect(Array.isArray(body.events)).toBe(true);
    expect(body.events.length).toBeGreaterThanOrEqual(5);
  });

  it('GET /v1/siem/events?query=WS-042 returns a coherent slice for WS-042', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/siem/events?query=WS-042',
      headers: AUTH_HEADER,
    });

    expect(res.statusCode).toBe(200);
    const body = res.json<EventsResponse>();
    expect(body.events.length).toBeGreaterThan(0);
    for (const event of body.events) {
      expect(event.host).toBe('WS-042');
    }
    // Coherent narrative: auth, then suspicious process, then outbound
    // connection to the incident's suspicious IP.
    const eventTypes = body.events.map((e) => e.eventType);
    expect(eventTypes).toContain('authentication');
    expect(eventTypes).toContain('process-creation');
    expect(eventTypes).toContain('network-connection');
  });

  it('GET /v1/siem/events?query=nonexistent returns an empty slice', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/siem/events?query=nonexistent-host-xyz',
      headers: AUTH_HEADER,
    });

    expect(res.statusCode).toBe(200);
    expect(res.json<EventsResponse>().events).toEqual([]);
  });

  it('GET /v1/siem/incidents/:id returns the seeded incident', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/siem/incidents/INC-2026-0042',
      headers: AUTH_HEADER,
    });

    expect(res.statusCode).toBe(200);
    const body = res.json<Incident>();
    expect(body).toMatchObject({
      id: 'INC-2026-0042',
      hostId: 'WS-042',
      suspiciousIp: '203.0.113.77',
      relatedUser: 'jdoe',
      status: 'open',
    });
  });

  it('GET /v1/siem/incidents/:id 404s for an unknown incident', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/siem/incidents/NOPE',
      headers: AUTH_HEADER,
    });

    expect(res.statusCode).toBe(404);
  });
});
