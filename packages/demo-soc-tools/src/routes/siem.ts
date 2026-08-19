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

  // ---- Phase 13 integration-pass routes ----
  //
  // `HttpToolAdapter` (manar-api's `src/tools/http-tool.adapter.ts`) calls
  // any registered HTTP `Tool` with a fixed, generic wire convention:
  // `POST {baseEndpoint}/{action.name}` with a JSON body `{ resource,
  // params }`. `edr.ts` already gained this same kind of wrapper route in
  // the Phase 7b integration pass (see that file's own doc comment); SIEM
  // never needed it until Phase 13's complete-demo scenario actually
  // drives `siem.search-events`/`siem.fetch-incident` through the real
  // gateway. Same store, same semantics as the REST-ish routes above,
  // just addressed the way `HttpToolAdapter` expects. Mounted under the
  // `/siem` prefix, so the full paths are `POST /v1/siem/search-events`
  // and `POST /v1/siem/fetch-incident`.
  fastify.post('/search-events', (request) => {
    const { resource } = request.body as { resource?: string };
    // `resource` doubles as the free-text query filter here (the sentinel
    // `"*"` — this package's and manar-api's shared "any resource"
    // convention, see docs/authorization-model.md — means "no filter,
    // return everything", matching `searchEvents(undefined)`).
    const query = !resource || resource === '*' ? undefined : resource;
    return { events: store.searchEvents(query) };
  });

  fastify.post('/fetch-incident', (request, reply) => {
    const { resource } = request.body as { resource: string };
    const incident = store.getIncident(resource);

    if (!incident) {
      return reply.code(404).send({ error: `Incident ${resource} not found` });
    }

    return incident;
  });
}
