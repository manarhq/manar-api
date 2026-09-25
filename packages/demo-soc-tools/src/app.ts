import Fastify, { type FastifyInstance } from 'fastify';
import { bearerAuthHook } from './auth/bearer-auth';
import healthRoutes from './routes/health';
import demoRoutes from './routes/demo';
import siemRoutes from './routes/siem';
import edrRoutes from './routes/edr';
import iamRoutes from './routes/iam';
import firewallRoutes from './routes/firewall';
import { DemoStore } from './state/store';
import microsoftFixtureRoutes from './microsoft/fixture';

export interface BuildAppOptions {
  /** The single static bearer token every `/v1/*` request must present. */
  apiKey: string;
  /** Passed straight through to Fastify's own `logger` option. */
  logger?: boolean | Record<string, unknown>;
}

/**
 * Builds (but does not `listen()`) the Fastify instance for this service.
 * Kept separate from `main.ts` so tests can exercise the full route tree
 * via `app.inject()` without binding a real port.
 *
 * Route layout:
 *  - `/health/live`, `/health/ready` — no auth (established convention).
 *  - `POST /_demo/reset` — no auth (dev-only convenience, see routes/demo.ts).
 *  - `/v1/*` — every route requires `Authorization: Bearer <apiKey>`,
 *    enforced by a single `preHandler` hook registered on the `/v1`
 *    encapsulation context so it applies uniformly to SIEM/EDR/IAM/
 *    Firewall without repeating the check in each route file.
 */
export function buildApp(options: BuildAppOptions): FastifyInstance {
  const app: FastifyInstance = Fastify({ logger: options.logger ?? true });
  const store = new DemoStore();

  void app.register(healthRoutes);
  void app.register(demoRoutes, { store });

  void app.register(
    (v1) => {
      v1.addHook('preHandler', bearerAuthHook(options.apiKey));

      void v1.register(siemRoutes, { prefix: '/siem', store });
      void v1.register(edrRoutes, { prefix: '/edr', store });
      void v1.register(iamRoutes, { prefix: '/iam', store });
      void v1.register(firewallRoutes, { prefix: '/firewall', store });
    },
    { prefix: '/v1' },
  );

  // DEMO FIXTURE mimic of the Entra token endpoint, Graph and Defender for
  // manar-api's Microsoft connector; its own auth, see microsoft/fixture.ts.
  void app.register(microsoftFixtureRoutes, { prefix: '/microsoft' });

  return app;
}
