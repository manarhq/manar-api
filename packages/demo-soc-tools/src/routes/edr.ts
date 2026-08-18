import type { FastifyInstance } from 'fastify';
import type { DemoStore } from '../state/store';

export interface EdrRouteOptions {
  store: DemoStore;
}

/**
 * EDR tool endpoints (Phase 7a design doc, "Endpoints" section):
 * `get-host`, `isolate-host`, `release-host`, `terminate-process`.
 */
export default function edrRoutes(
  fastify: FastifyInstance,
  opts: EdrRouteOptions,
): void {
  const { store } = opts;

  fastify.get('/hosts/:id', (request, reply) => {
    const { id } = request.params as { id: string };
    const host = store.getHost(id);

    if (!host) {
      return reply.code(404).send({ error: `Host ${id} not found` });
    }

    return host;
  });

  fastify.post('/hosts/:id/isolate', (request, reply) => {
    const { id } = request.params as { id: string };
    const host = store.isolateHost(id);

    if (!host) {
      return reply.code(404).send({ error: `Host ${id} not found` });
    }

    return host;
  });

  fastify.post('/hosts/:id/release', (request, reply) => {
    const { id } = request.params as { id: string };
    const host = store.releaseHost(id);

    if (!host) {
      return reply.code(404).send({ error: `Host ${id} not found` });
    }

    return host;
  });

  fastify.post('/hosts/:id/processes/:pid/terminate', (request, reply) => {
    const { id, pid } = request.params as { id: string; pid: string };
    const pidNumber = Number(pid);

    if (!Number.isInteger(pidNumber)) {
      return reply.code(400).send({ error: `Invalid pid: ${pid}` });
    }

    const result = store.terminateProcess(id, pidNumber);

    if (!result.ok) {
      const message =
        result.reason === 'host-not-found'
          ? `Host ${id} not found`
          : `Process ${pid} not found on host ${id}`;
      return reply.code(404).send({ error: message });
    }

    return result.host;
  });
}
