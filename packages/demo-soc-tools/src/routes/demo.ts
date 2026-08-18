import type { FastifyInstance } from 'fastify';
import type { DemoStore } from '../state/store';

export interface DemoRouteOptions {
  store: DemoStore;
}

/**
 * `POST /_demo/reset` — deliberately NOT auth-gated (Phase 7a design doc:
 * "not auth-gated, dev-only convenience"). Restores deterministic seed
 * state so tests and repeated demo runs always start clean, regardless
 * of what a previous run mutated (isolated hosts, disabled users,
 * terminated processes, blocked IPs, etc.).
 */
export default function demoRoutes(
  fastify: FastifyInstance,
  opts: DemoRouteOptions,
): void {
  const { store } = opts;

  fastify.post('/_demo/reset', () => {
    store.reset();
    return { status: 'reset' };
  });
}
