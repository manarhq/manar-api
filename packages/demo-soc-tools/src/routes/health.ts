import type { FastifyInstance } from 'fastify';

export interface HealthStatus {
  status: 'ok';
}

/**
 * `/health/live` + `/health/ready`, matching manar-api's own established
 * convention (see `src/health/health.controller.ts` in the repo root):
 * liveness is unconditional once the process answers HTTP at all;
 * readiness has no downstream dependency to check yet (this service's
 * only "dependency" is its own in-memory store, which is always ready
 * once the process is up), so it intentionally always reports ready
 * rather than faking a check that doesn't exist.
 */
export default function healthRoutes(fastify: FastifyInstance): void {
  fastify.get('/health/live', (): HealthStatus => {
    return { status: 'ok' };
  });

  fastify.get('/health/ready', (): HealthStatus => {
    return { status: 'ok' };
  });
}
