import type { FastifyInstance } from 'fastify';
import type { DemoStore } from '../state/store';

export interface FirewallRouteOptions {
  store: DemoStore;
}

/**
 * Firewall tool endpoints (Phase 7a design doc, "Endpoints" section):
 * `lookup-ip`, `block-ip`, `unblock-ip`.
 */
export default function firewallRoutes(
  fastify: FastifyInstance,
  opts: FirewallRouteOptions,
): void {
  const { store } = opts;

  fastify.get('/lookup', (request, reply) => {
    const { ip } = request.query as { ip?: string };

    if (!ip) {
      return reply
        .code(400)
        .send({ error: 'Query parameter "ip" is required' });
    }

    return store.lookupIp(ip);
  });

  fastify.post('/block', (request, reply) => {
    const body = request.body as { ip?: string } | undefined;

    if (!body?.ip) {
      return reply.code(400).send({ error: 'Request body must include "ip"' });
    }

    return store.blockIp(body.ip);
  });

  fastify.post('/unblock', (request, reply) => {
    const body = request.body as { ip?: string } | undefined;

    if (!body?.ip) {
      return reply.code(400).send({ error: 'Request body must include "ip"' });
    }

    return store.unblockIp(body.ip);
  });
}
