import { createServer, type Server } from 'node:http';
import { Logger } from '@nestjs/common';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  collectDefaultMetrics,
  Counter,
  Gauge,
  Histogram,
  Registry,
} from 'prom-client';

/**
 * Prometheus metrics for SLOs (docs/slo/). Names follow the OpenTelemetry
 * HTTP semantic conventions as exported to Prometheus
 * (`http.server.request.duration` -> `http_server_request_duration_seconds`),
 * so dashboards and rules stay the same if the exporter changes.
 *
 * Labels never carry tenant data, ids, raw URLs or secrets: the route label
 * is the route template, and decision reasons are the fixed reason codes.
 * Recording is in-process only; nothing here can block or change a decision.
 */
export const MetricsConfigSchema = z.object({
  /** Internal-only /metrics listener. 0 disables it. Never exposed by the ingress. */
  METRICS_PORT: z.coerce.number().int().min(0).max(65535).default(9464),
  /** The Temporal worker's own metrics port, so an API and a worker on one host never collide. 0 disables. */
  WORKER_METRICS_PORT: z.coerce.number().int().min(0).max(65535).default(9465),
});

/** OTel's recommended http.server.request.duration buckets, in seconds. */
const DURATION_BUCKETS = [
  0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10,
];

export const registry = new Registry();
registry.setDefaultLabels({ service_name: 'manar-api' });
collectDefaultMetrics({ register: registry });

const httpDuration = new Histogram({
  name: 'http_server_request_duration_seconds',
  help: 'Duration of HTTP server requests.',
  labelNames: [
    'http_request_method',
    'http_route',
    'http_response_status_code',
    'listener',
  ],
  buckets: DURATION_BUCKETS,
  registers: [registry],
});

const decisions = new Counter({
  name: 'manar_authorization_decisions_total',
  help: 'Authorization decisions by outcome and reason code.',
  labelNames: ['decision', 'reason'],
  registers: [registry],
});

const decisionDuration = new Histogram({
  name: 'manar_authorization_decision_duration_seconds',
  help: 'Time to evaluate and record one authorization decision.',
  labelNames: ['decision'],
  buckets: DURATION_BUCKETS,
  registers: [registry],
});

const fallbackActive = new Gauge({
  name: 'manar_rate_limit_fallback_active',
  help: '1 while a fail-open rate-limit surface uses in-memory limits because Redis is unavailable.',
  labelNames: ['surface'],
  registers: [registry],
});

const fallbackRequests = new Counter({
  name: 'manar_rate_limit_fallback_requests_total',
  help: 'Requests limited in memory because Redis was unavailable.',
  labelNames: ['surface'],
  registers: [registry],
});

export function recordRateLimitFallback(
  surface: string,
  active: boolean,
): void {
  fallbackActive.set({ surface }, active ? 1 : 0);
  if (active) fallbackRequests.inc({ surface });
}

const cloudMcpRejections = new Counter({
  name: 'manar_cloud_mcp_token_rejections_total',
  help: 'Requests the public cloud-agent MCP endpoint refused, by reason (docs/cloud-agents.md).',
  labelNames: ['reason'],
  registers: [registry],
});

export function recordCloudMcpRejection(reason: string): void {
  cloudMcpRejections.inc({ reason });
}

const cloudMcpPendingClients = new Counter({
  name: 'manar_cloud_mcp_pending_clients_total',
  help: 'Self-registered clients waiting for a tenant admin to confirm them for a ChatGPT agent. Alert on any increase.',
  registers: [registry],
});

export function recordCloudMcpPendingClient(): void {
  cloudMcpPendingClients.inc();
}

const licenseStatus = new Gauge({
  name: 'manar_license_status',
  help: 'Licence status: 1 for the current status, 0 for the others. Soft limit, never enforced.',
  labelNames: ['status'],
  registers: [registry],
});

const licenseExpiry = new Gauge({
  name: 'manar_license_expiry_timestamp_seconds',
  help: 'Expiry of the verified licence, Unix seconds; 0 when no licence is verified.',
  registers: [registry],
});

const licenseLimit = new Gauge({
  name: 'manar_license_limit',
  help: 'Licensed amount per resource; absent when unlimited or no licence is verified.',
  labelNames: ['resource'],
  registers: [registry],
});

const licenseUsage = new Gauge({
  name: 'manar_license_usage',
  help: 'Current usage per licensed resource; absent when it could not be counted.',
  labelNames: ['resource'],
  registers: [registry],
});

/** Sets the licence gauges (src/licensing). Label values are fixed sets, never tenant data. */
export function recordLicense(
  status: string,
  statuses: readonly string[],
  expiresAt: string | null,
  limits: Record<string, number | null> | null,
  usage: Record<string, number | null>,
): void {
  for (const s of statuses)
    licenseStatus.set({ status: s }, s === status ? 1 : 0);
  licenseExpiry.set(expiresAt ? Date.parse(expiresAt) / 1000 : 0);
  for (const [resource, used] of Object.entries(usage)) {
    const max = limits?.[resource] ?? null;
    if (max === null) licenseLimit.remove({ resource });
    else licenseLimit.set({ resource }, max);
    if (used === null) licenseUsage.remove({ resource });
    else licenseUsage.set({ resource }, used);
  }
}

const REASON_CODE = /^[a-z][a-z0-9_]{0,63}$/;

/** Bounded label: a reason code passes through, anything else is "other". */
export function reasonLabel(reason: string | undefined): string {
  if (reason === undefined) return 'none';
  return REASON_CODE.test(reason) ? reason : 'other';
}

/**
 * Records one decision. `decision` is ALLOW, APPROVAL_REQUIRED, DENY, or
 * ERROR when recording the decision itself failed (the caller got a 503).
 */
export function recordDecision(
  startedAt: bigint,
  decision: string,
  reason: string | undefined,
): void {
  const seconds = Number(process.hrtime.bigint() - startedAt) / 1e9;
  decisions.inc({ decision, reason: reasonLabel(reason) });
  decisionDuration.observe({ decision }, seconds);
}

/** Adds the request-duration hook to a Fastify instance (both listeners). */
export function instrumentHttp(
  fastify: FastifyInstance,
  listener: 'human' | 'agent',
): void {
  fastify.addHook('onResponse', (request, reply, done) => {
    httpDuration.observe(
      {
        http_request_method: request.method,
        // Template (e.g. /approvals/:id), never the raw URL; unmatched
        // requests (404 scans) share one label so they cannot blow up
        // cardinality.
        http_route: request.routeOptions.url ?? 'unmatched',
        http_response_status_code: String(reply.statusCode),
        listener,
      },
      reply.elapsedTime / 1000,
    );
    done();
  });
}

/**
 * Serves GET /metrics on its own port. A bind failure is logged, not
 * thrown: losing metrics must never take the decision path down with it.
 */
export function startMetricsServer(
  port: number,
  serviceName = 'manar-api',
): Server | undefined {
  if (port === 0) return undefined;
  registry.setDefaultLabels({ service_name: serviceName });
  const logger = new Logger('Metrics');
  const server = createServer((req, res) => {
    if (req.method !== 'GET' || req.url !== '/metrics') {
      res.writeHead(404).end();
      return;
    }
    registry.metrics().then(
      (body) => {
        res.writeHead(200, { 'Content-Type': registry.contentType }).end(body);
      },
      () => res.writeHead(500).end(),
    );
  });
  server.on('error', (error) => {
    logger.error(`metrics listener on :${port} failed: ${error.message}`);
  });
  server.listen(port, '0.0.0.0');
  return server;
}
