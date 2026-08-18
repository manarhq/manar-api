import type { FastifyInstance } from 'fastify';
import type { DemoStore } from '../state/store';

export interface SiemRouteOptions {
  store: DemoStore;
}

/**
 * SIEM tool endpoints (Phase 7a design doc, "Endpoints" section):
 * `search-events` and `fetch-incident`.
 */
export default function siemRoutes(
  fastify: FastifyInstance,
  opts: SiemRouteOptions,
): void {
  const { store } = opts;

  fastify.get('/events', (request) => {
    const { query } = request.query as { query?: string };
    return { events: store.searchEvents(query) };
  });

  fastify.get('/incidents/:id', (request, reply) => {
    const { id } = request.params as { id: string };
    const incident = store.getIncident(id);

    if (!incident) {
      return reply.code(404).send({ error: `Incident ${id} not found` });
    }

    return incident;
  });
}
