import { readFileSync } from 'node:fs';
import { NestFactory } from '@nestjs/core';
import type { INestApplication } from '@nestjs/common';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { ConfigService } from '@nestjs/config';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';
import { AppModule } from './app.module';
import { AgentMtlsAppModule } from './agent-mtls/agent-mtls-app.module';
import { allowLargeLlmBodies } from './agent-runtime/llm-proxy.controller';
import { validate } from './config/env.validation';
import { httpAdapterOptions } from './config/trusted-proxy';
import type { AppConfig } from './config/env.validation';
import { setupOpenApiDocs } from './openapi/setup-openapi-docs';
import { setupCors, setupHelmet } from './security/setup-security';
import { instrumentHttp, startMetricsServer } from './metrics/metrics';

async function bootstrap(): Promise<void> {
  // Validated once, directly against process.env, before either Nest
  // application exists — the mTLS listener's https options
  // (cert/key/ca/requestCert) must be resolved at FastifyAdapter
  // *construction* time, before Nest's DI container (and therefore
  // ConfigService) is available. Same bootstrap-time constraint
  // agent-mtls.config.ts's doc comment describes.
  const bootstrapConfig = validate(process.env);

  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    // MANAR_TRUSTED_PROXY_CIDRS: request.ip is the real caller behind cloudflared and Traefik.
    new FastifyAdapter(httpAdapterOptions(bootstrapConfig)),
    // rawBody: the Stripe webhook verifies its signature over the exact bytes.
    { bufferLogs: true, rawBody: true },
  );
  app.useLogger(app.get(WINSTON_MODULE_NEST_PROVIDER));

  const configService = app.get(ConfigService<AppConfig, true>);
  const port = configService.get('PORT', { infer: true });
  instrumentHttp(app.getHttpAdapter().getInstance(), 'human');
  // RFC 8058 one-click unsubscribe (and its confirm-page form) POSTs form-encoded; nothing else
  // on this listener takes a form body, so the parser is limited to that one route.
  app
    .getHttpAdapter()
    .getInstance()
    .addContentTypeParser(
      'application/x-www-form-urlencoded',
      { parseAs: 'string', bodyLimit: 1024 },
      (req, _body, done) =>
        req.url.startsWith('/public/unsubscribe/')
          ? done(null, {})
          : done(
              Object.assign(new Error('Unsupported Media Type'), {
                statusCode: 415,
              }),
            ),
    );
  setupHelmet(app);
  setupCors(app, configService);
  setupOpenApiDocs(app, configService);
  enableGracefulShutdown(app);
  await app.listen(port, '0.0.0.0');

  const agentMtlsApp = await NestFactory.create<NestFastifyApplication>(
    AgentMtlsAppModule,
    new FastifyAdapter({
      https: {
        cert: readFileSync(bootstrapConfig.AGENT_MTLS_SERVER_CERT_PATH),
        key: readFileSync(bootstrapConfig.AGENT_MTLS_SERVER_KEY_PATH),
        // The trust anchor for CLIENT certificates (mutual TLS) — the
        // FULL chain (intermediate + root, see agent-mtls.config.ts's doc
        // comment for why not the intermediate alone). Node's TLS layer
        // refuses the handshake outright for a client cert that doesn't
        // chain to this, before AgentMtlsGuard (defense in depth beyond
        // that) ever runs.
        ca: readFileSync(bootstrapConfig.AGENT_MTLS_CLIENT_CA_PATH),
        requestCert: true,
        rejectUnauthorized: true,
      },
    }),
    { bufferLogs: true },
  );
  agentMtlsApp.useLogger(agentMtlsApp.get(WINSTON_MODULE_NEST_PROVIDER));
  allowLargeLlmBodies(agentMtlsApp.getHttpAdapter().getInstance());
  instrumentHttp(agentMtlsApp.getHttpAdapter().getInstance(), 'agent');
  setupHelmet(agentMtlsApp);
  enableGracefulShutdown(agentMtlsApp);
  await agentMtlsApp.listen(bootstrapConfig.AGENT_MTLS_PORT, '0.0.0.0');
  startMetricsServer(bootstrapConfig.METRICS_PORT);
}

/**
 * Turns SIGTERM/SIGINT into an orderly Nest shutdown instead of an abrupt
 * process death.
 *
 * Release 2026-11-11 reliability fix: `enableShutdownHooks()` appeared
 * nowhere in this codebase, so **no `onModuleDestroy` hook had ever run in
 * production**. On every rollout, scale-down, node drain, and eviction, the
 * process was simply killed — which meant:
 *
 * - `TenantDatabaseManager.onModuleDestroy` never disconnected its cached
 *   per-tenant Prisma clients (up to `TENANT_DB_CLIENT_CACHE_MAX` of them,
 *   each holding a real Postgres connection pool). Postgres kept those
 *   backends open until its own TCP keepalive reaped them, so a rolling
 *   restart leaked server-side connections against `max_connections` at
 *   exactly the moment the replacement replicas were trying to open theirs.
 * - `KafkaPublisherService`'s producer never flushed or disconnected —
 *   in-flight audit envelopes were dropped rather than sent, and the broker
 *   was left to time the producer session out.
 * - The three Redis clients and `ControlPrismaService` were likewise never
 *   closed.
 * - Fastify never stopped accepting new connections *before* the process
 *   went away, so every in-flight request at that instant became a client-
 *   visible 502 rather than a completed response.
 *
 * `enableShutdownHooks` fixes all of that: on the signal, Nest calls
 * `onModuleDestroy`/`beforeApplicationShutdown` across the module graph,
 * then closes the HTTP server, then `onApplicationShutdown`. Requests still
 * in flight after `onModuleDestroy` therefore still run; `AuditService`'s
 * batcher flushes their audit records at once rather than refusing them.
 *
 * Pairing this with the Helm `preStop` sleep and `terminationGracePeriodSeconds`
 * (deploy/helm/manar-api/templates/deployment.yaml) is what makes rollouts
 * actually zero-drop: the sleep covers the window during which this pod has
 * been sent SIGTERM but kube-proxy/the ingress have not yet finished
 * removing it from their endpoint tables, and the grace period gives the
 * hooks above room to finish before SIGKILL.
 *
 * Registered *before* `listen()` so a SIGTERM arriving during a slow
 * startup is still handled gracefully rather than racing the listener.
 *
 * Called once per Nest application, and this process runs two (the human
 * HTTP app and the agent mTLS app) with entirely separate DI containers and
 * therefore separate Prisma/Kafka/Redis instances — both need closing.
 * Nest's handler re-raises the signal to itself after its own cleanup
 * finishes; because the other application's listener is still installed at
 * that moment, that re-raise is absorbed rather than killing the process,
 * and the process only actually terminates once the *second* application
 * has finished closing too.
 */
function enableGracefulShutdown(app: INestApplication): void {
  app.enableShutdownHooks();
}

void bootstrap();
