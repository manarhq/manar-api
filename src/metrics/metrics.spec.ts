import { request as httpGet } from 'node:http';
import type { AddressInfo } from 'node:net';
import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import {
  instrumentHttp,
  reasonLabel,
  recordDecision,
  registry,
  startMetricsServer,
} from './metrics';

async function sample(name: string, labels: Record<string, string>) {
  const metric = await registry.getSingleMetric(name)?.get();
  return metric?.values.find((v) =>
    Object.entries(labels).every(([k, val]) => v.labels[k] === val),
  )?.value;
}

describe('metrics', () => {
  it('keeps reason codes and buckets anything else as "other"', () => {
    expect(reasonLabel('enforcement_dependency_unavailable')).toBe(
      'enforcement_dependency_unavailable',
    );
    expect(reasonLabel(undefined)).toBe('none');
    // Free text or an id must never become a label value.
    expect(reasonLabel('Denied for tenant acme-uae: user 42')).toBe('other');
    expect(reasonLabel('x'.repeat(65))).toBe('other');
  });

  it('counts a decision and observes its duration', async () => {
    const before =
      (await sample('manar_authorization_decisions_total', {
        decision: 'DENY',
        reason: 'not_authorized',
      })) ?? 0;
    recordDecision(process.hrtime.bigint(), 'DENY', 'not_authorized');
    expect(
      await sample('manar_authorization_decisions_total', {
        decision: 'DENY',
        reason: 'not_authorized',
      }),
    ).toBe(before + 1);
    const histogram = await registry
      .getSingleMetric('manar_authorization_decision_duration_seconds')
      ?.get();
    // Histogram values carry metricName (_bucket, _sum, _count) at runtime.
    const values = (histogram?.values ?? []) as {
      metricName?: string;
      labels: Record<string, unknown>;
      value: number;
    }[];
    const count = values.find(
      (v) => v.metricName?.endsWith('_count') && v.labels.decision === 'DENY',
    );
    expect(count?.value).toBeGreaterThan(0);
  });

  it('labels HTTP requests with the route template, never the raw URL', async () => {
    const app = Fastify();
    instrumentHttp(app, 'human');
    app.get('/approvals/:id', () => ({ ok: true }));
    await app.inject({ method: 'GET', url: '/approvals/abc-123' });
    await app.inject({ method: 'GET', url: '/no/such/route' });

    const text = await registry.metrics();
    expect(text).toContain('http_route="/approvals/:id"');
    expect(text).not.toContain('abc-123');
    expect(text).toContain('http_route="unmatched"');
    expect(text).toContain('http_response_status_code="404"');
    await app.close();
  });

  it('port 0 disables the listener', () => {
    expect(startMetricsServer(0)).toBeUndefined();
  });

  it('serves /metrics on its own port with the service name', async () => {
    const own = startMetricsServer(39_464);
    await new Promise((r) => own?.once('listening', r));
    const port = (own?.address() as AddressInfo).port;
    const body = await new Promise<string>((resolve, reject) => {
      httpGet({ port, path: '/metrics' }, (res) => {
        let data = '';
        res.on('data', (c: Buffer) => (data += c.toString()));
        res.on('end', () => resolve(data));
      })
        .on('error', reject)
        .end();
    });
    expect(body).toContain('service_name="manar-api"');
    expect(body).toContain('http_server_request_duration_seconds_bucket');
    own?.close();
  });
});
