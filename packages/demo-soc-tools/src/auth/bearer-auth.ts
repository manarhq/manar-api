import type { FastifyReply, FastifyRequest } from 'fastify';

/**
 * Builds a Fastify `preHandler` hook that requires an exact
 * `Authorization: Bearer <apiKey>` match — the single static token this
 * service authenticates with (`DEMO_TOOLS_API_KEY`, see
 * `src/config/env.ts`). Sending the reply is sufficient to short-circuit
 * the rest of the request lifecycle in Fastify; no further signalling is
 * needed once `reply.send()` has been called.
 */
export function bearerAuthHook(apiKey: string) {
  return async (
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<void> => {
    const header = request.headers.authorization;

    if (header !== `Bearer ${apiKey}`) {
      await reply.code(401).send({ error: 'Unauthorized' });
    }
  };
}
