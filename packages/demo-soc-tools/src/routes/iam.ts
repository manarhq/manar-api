import type { FastifyInstance } from 'fastify';
import type { DemoStore } from '../state/store';

export interface IamRouteOptions {
  store: DemoStore;
}

/**
 * IAM tool endpoints (Phase 7a design doc, "Endpoints" section):
 * `get-user`, `disable-user`.
 */
export default function iamRoutes(
  fastify: FastifyInstance,
  opts: IamRouteOptions,
): void {
  const { store } = opts;

  fastify.get('/users/:id', (request, reply) => {
    const { id } = request.params as { id: string };
    const user = store.getUser(id);

    if (!user) {
      return reply.code(404).send({ error: `User ${id} not found` });
    }

    return user;
  });

  fastify.post('/users/:id/disable', (request, reply) => {
    const { id } = request.params as { id: string };
    const user = store.disableUser(id);

    if (!user) {
      return reply.code(404).send({ error: `User ${id} not found` });
    }

    return user;
  });
}
