import {
  agentListenerBound,
  expectAgentListener,
} from './agent-listener-state';
import { createServer as createHttpServer } from 'node:http';
import { createServer, type AddressInfo, type Server } from 'node:net';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import type { ControlPrismaService } from '../database/control-prisma.service';
import type { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { ReadinessService } from './readiness.service';

/**
 * Tests for the *wiring* half of readiness — which dependencies exist and,
 * critically, which of them are allowed to take this replica out of the
 * Service's endpoint list. `readiness.spec.ts` covers the engine's
 * behaviour; this file covers the policy encoded in the probe list, because
 * a probe accidentally marked `required: true` is a one-character change
 * that converts any single dependency's outage into a total outage.
 *
 * Collaborators are plain in-memory fakes, no Nest DI container — same
 * house style as `jwt-auth.guard.spec.ts`.
 */

/**
 * Every dependency address defaults to port 1 on the loopback interface:
 * nothing listens there, so the TCP probes fail fast and deterministically
 * without this suite ever touching a real network dependency.
 */
const UNREACHABLE = '127.0.0.1:1';

/**
 * A real listening socket that accepts and immediately drops connections,
 * so the one *required* TCP-probed dependency (OpenFGA) can be made
 * genuinely reachable. Exercising the real `checkTcpReachable` against a
 * real socket is the point — a fake here would test nothing about the
 * probe that actually gates traffic.
 */
let reachableServer: Server;
let reachableAddress: string;

beforeAll(async () => {
  reachableServer = createServer((socket) => socket.destroy());
  await new Promise<void>((resolve) => {
    reachableServer.listen(0, '127.0.0.1', resolve);
  });
  const address = reachableServer.address();
  if (address === null || typeof address === 'string') {
    throw new Error('Expected an ephemeral TCP port for the readiness fixture');
  }
  reachableAddress = `127.0.0.1:${address.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    reachableServer.close((error) => (error ? reject(error) : resolve()));
  });
});

function makeService(
  overrides: {
    controlQuery?: () => Promise<unknown>;
    activeTenantIds?: string[];
    tenantCheckHealth?: (tenantId: string) => Promise<boolean>;
    /** Point the required OpenFGA probe at the live socket above. */
    openfgaReachable?: boolean;
    openbaoAddr?: string;
  } = {},
): ReadinessService {
  const configService = {
    get: (key: string) => {
      if (key === 'OPENBAO_ADDR' && overrides.openbaoAddr) {
        return overrides.openbaoAddr;
      }
      if (key === 'OPENFGA_API_URL' && overrides.openfgaReachable) {
        return `http://${reachableAddress}`;
      }
      return key === 'REDIS_URL' ? `redis://${UNREACHABLE}` : UNREACHABLE;
    },
  } as unknown as ConfigService<AppConfig, true>;

  const controlPrisma = {
    $queryRaw:
      overrides.controlQuery ?? (() => Promise.resolve([{ '?column?': 1 }])),
    tenant: {
      findMany: vi
        .fn()
        .mockResolvedValue(
          (overrides.activeTenantIds ?? []).map((id) => ({ id })),
        ),
    },
  } as unknown as ControlPrismaService;

  const tenantDatabaseManager = {
    checkHealth:
      overrides.tenantCheckHealth ??
      ((): Promise<boolean> => Promise.resolve(true)),
  } as unknown as TenantDatabaseManager;

  return new ReadinessService(
    configService,
    controlPrisma,
    tenantDatabaseManager,
  );
}

describe('ReadinessService probe list', () => {
  it('covers every dependency the chart’s NetworkPolicy egress list allows', () => {
    // Ten probes for the nine dependencies in
    // deploy/helm/manar-api/values.yaml's `networkPolicy.egress`
    // (minus the demo tool server), plus this process's own agent mTLS
    // listener: Postgres gets two, because the control
    // plane and a tenant's own database fail independently and carry
    // different consequences.
    expect(
      makeService()
        .probes.map((probe) => probe.name)
        .sort(),
    ).toEqual([
      'agent-listener',
      'ai-advisory',
      'kafka',
      'keycloak',
      'openbao',
      'openfga',
      'opensearch',
      'postgres-control',
      'postgres-tenant',
      'redis',
      'temporal',
    ]);
  });

  it('marks ONLY the control database, OpenFGA and the agent listener as required', () => {
    const required = makeService()
      .probes.filter((probe) => probe.required)
      .map((probe) => probe.name)
      .sort();

    // Every replica shares every dependency, so a `required` flag turns
    // that dependency's outage into a *total* outage. Only the two that
    // sit on every authenticated request path — and that would 500 rather
    // than degrade — earn it.
    expect(required).toEqual(['agent-listener', 'openfga', 'postgres-control']);
  });

  it('never marks the AI advisory service required', () => {
    const aiAdvisory = makeService().probes.find(
      (probe) => probe.name === 'ai-advisory',
    );

    // Section 80: an AI outage must not change a deterministic outcome, and
    // it must not become a perpetual readiness failure either.
    expect(aiAdvisory?.required).toBe(false);
  });

  it('gives every probe a human-readable impact line for whoever gets paged', () => {
    for (const probe of makeService().probes) {
      expect(probe.impact.length).toBeGreaterThan(20);
    }
  });
});

describe('ReadinessService.check', () => {
  it('stays ready when every optional dependency, AI advisory included, is unreachable', async () => {
    const report = await makeService({
      activeTenantIds: ['tenant-1'],
      openfgaReachable: true,
    }).check();

    expect(report.ready).toBe(true);
    expect(report.status).toBe('degraded');
    expect(report.dependencies['ai-advisory']?.status).toBe('unhealthy');
    expect(report.dependencies['kafka']?.status).toBe('unhealthy');
    // The one required dependency reachable in this fixture is the control
    // database, whose probe is a real query rather than a TCP connect.
    expect(report.dependencies['postgres-control']?.status).toBe('ok');
  });

  it('is not ready when the control database query fails', async () => {
    const report = await makeService({
      controlQuery: () => Promise.reject(new Error('connection refused')),
    }).check();

    expect(report.ready).toBe(false);
    expect(report.status).toBe('unhealthy');
    expect(report.dependencies['postgres-control']?.error).toContain(
      'connection refused',
    );
  });

  it('is not ready when the required OpenFGA store is unreachable', async () => {
    const report = await makeService({ openfgaReachable: false }).check();

    expect(report.ready).toBe(false);
    expect(report.dependencies['openfga']?.status).toBe('unhealthy');
    expect(report.dependencies['openfga']?.required).toBe(true);
  });

  it('reports the tenant-database probe as degraded, never failing, when a sampled tenant’s database is down', async () => {
    const report = await makeService({
      activeTenantIds: ['tenant-1'],
      tenantCheckHealth: () => Promise.reject(new Error('tenant db down')),
      openfgaReachable: true,
    }).check();

    // One tenant's database being unreachable must not evict this replica
    // and break every *other* tenant.
    expect(report.dependencies['postgres-tenant']?.status).toBe('unhealthy');
    expect(report.dependencies['postgres-tenant']?.required).toBe(false);
    expect(report.ready).toBe(true);
  });

  it('reports the tenant-database probe as degraded when there are no ACTIVE tenants to sample', async () => {
    const report = await makeService({
      activeTenantIds: [],
      openfgaReachable: true,
    }).check();

    // A fresh control plane has nothing to check, and a probe that observed
    // nothing must not report a green it did not earn.
    expect(report.dependencies['postgres-tenant']?.status).toBe('degraded');
    expect(report.ready).toBe(true);
  });
});

describe('ReadinessService OpenBao probe (F1)', () => {
  async function openBaoFixture(status: number) {
    const server = createHttpServer((_req, res) => {
      res.statusCode = status;
      res.end(status === 200 ? '-----BEGIN CERTIFICATE-----' : '');
    });
    await new Promise<void>((resolve) =>
      server.listen(0, '127.0.0.1', resolve),
    );
    const { port } = server.address() as AddressInfo;
    return { server, addr: `http://127.0.0.1:${port}` };
  }

  it('reports OpenBao unhealthy when it answers but the agent PKI is gone', async () => {
    const { server, addr } = await openBaoFixture(404);
    try {
      const report = await makeService({ openbaoAddr: addr }).check();
      expect(report.dependencies.openbao?.status).not.toBe('ok');
    } finally {
      server.close();
    }
  });

  it('reports OpenBao ok when the agent PKI is mounted', async () => {
    const { server, addr } = await openBaoFixture(200);
    try {
      const report = await makeService({ openbaoAddr: addr }).check();
      expect(report.dependencies.openbao?.status).toBe('ok');
    } finally {
      server.close();
    }
  });
});

describe('agent mTLS listener readiness (E-017)', () => {
  it('is not ready while the process expects the agent listener and it is not bound yet', async () => {
    expectAgentListener();
    const before = await makeService({ openfgaReachable: true }).check();
    expect(before.ready).toBe(false);
    expect(before.dependencies['agent-listener']?.status).toBe('unhealthy');

    agentListenerBound();
    const after = await makeService({ openfgaReachable: true }).check();
    expect(after.dependencies['agent-listener']?.status).toBe('ok');
    expect(after.ready).toBe(true);
  });
});
