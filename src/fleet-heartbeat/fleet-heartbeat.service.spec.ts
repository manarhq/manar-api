import { generateKeyPairSync, verify } from 'node:crypto';
import type { ConfigService } from '@nestjs/config';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AppConfig } from '../config/env.validation';
import type { ControlPrismaService } from '../database/control-prisma.service';
import type { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import type { ReadinessService } from '../health/readiness.service';
import type { OpenBaoKvClient } from '../openbao/openbao-kv.client';
import { FleetHeartbeatService } from './fleet-heartbeat.service';

const keys = generateKeyPairSync('ed25519');
const TENANT_ID = '11111111-2222-4333-8444-555555555555';
const DEPLOYMENT_ID = '99999999-8888-4777-8666-555555555555';

function service(env: Record<string, unknown>) {
  const values: Record<string, unknown> = {
    FLEET_HEARTBEAT_INTERVAL_MINUTES: 5,
    FLEET_HEARTBEAT_KEY_PATH: 'fleet/heartbeat-signing-key',
    ...env,
  };
  const config = { get: (k: string) => values[k] } as unknown as ConfigService<
    AppConfig,
    true
  >;
  const readiness = {
    check: () =>
      Promise.resolve({
        status: 'degraded',
        ready: true,
        checkedAt: new Date().toISOString(),
        dependencies: {
          'postgres-control': {
            status: 'ok',
            required: true,
            impact: '',
            durationMs: 1,
          },
          openbao: {
            status: 'unhealthy',
            required: false,
            impact: '',
            durationMs: 1,
            error: 'x',
          },
        },
      }),
  } as unknown as ReadinessService;
  const control = {
    tenant: {
      findMany: () =>
        Promise.resolve([{ id: TENANT_ID, status: 'ACTIVE', slug: 'acme' }]),
    },
  } as unknown as ControlPrismaService;
  const tenants = {
    getClient: () =>
      Promise.resolve({
        agent: { count: (a?: unknown) => Promise.resolve(a ? 2 : 3) },
      }),
  } as unknown as TenantDatabaseManager;
  const kv = {
    readSecret: () =>
      Promise.resolve({
        privateKeyPem: keys.privateKey
          .export({ type: 'pkcs8', format: 'pem' })
          .toString(),
      }),
  } as unknown as OpenBaoKvClient;
  return new FleetHeartbeatService(config, readiness, control, tenants, kv);
}

afterEach(() => vi.restoreAllMocks());

describe('FleetHeartbeatService', () => {
  it('is off by default: no URL, no timer, no request', () => {
    const interval = vi.spyOn(global, 'setInterval');
    const fetchSpy = vi.spyOn(global, 'fetch');
    service({}).onApplicationBootstrap();
    expect(interval).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('does not start without a deployment id', () => {
    const interval = vi.spyOn(global, 'setInterval');
    service({
      FLEET_HEARTBEAT_URL: 'http://fleet.internal/heartbeats',
    }).onApplicationBootstrap();
    expect(interval).not.toHaveBeenCalled();
  });

  it('signs a payload of versions, health, backup and counts only', async () => {
    const env = await service({
      FLEET_DEPLOYMENT_ID: DEPLOYMENT_ID,
      MANAR_GIT_SHA: 'abc1234',
    }).signedEnvelope();
    const bytes = Buffer.from(env.payload, 'base64');
    expect(
      verify(null, bytes, keys.publicKey, Buffer.from(env.signature, 'base64')),
    ).toBe(true);
    const payload = JSON.parse(bytes.toString()) as Record<string, unknown>;
    expect(Object.keys(payload).sort()).toEqual([
      'backup',
      'counts',
      'deploymentId',
      'gitSha',
      'health',
      'nonce',
      'timestamp',
      'v',
      'version',
    ]);
    expect(payload).toMatchObject({
      v: 1,
      deploymentId: DEPLOYMENT_ID,
      gitSha: 'abc1234',
      health: {
        status: 'degraded',
        checks: { 'postgres-control': 'up', openbao: 'down' },
      },
      backup: {
        status: 'unknown',
        lastBackupAt: null,
        lastRestoreTestAt: null,
      },
      counts: { tenants: 1, tenantsActive: 1, agents: 3, agentsActive: 2 },
    });
    const text = bytes.toString();
    expect(text).not.toContain(TENANT_ID);
    expect(text).not.toContain('acme');
  });

  it('uses a fresh nonce every time', async () => {
    const s = service({ FLEET_DEPLOYMENT_ID: DEPLOYMENT_ID });
    const a = await s.payload();
    const b = await s.payload();
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.nonce).toMatch(/^[0-9a-f]{32}$/);
  });
});
