import { generateKeyPairSync, verify } from 'node:crypto';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ConfigService } from '@nestjs/config';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AppConfig } from '../config/env.validation';
import type { ControlPrismaService } from '../database/control-prisma.service';
import type { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import type { ReadinessService } from '../health/readiness.service';
import type { OpenBaoKvClient } from '../openbao/openbao-kv.client';
import type { PlatformOpsService } from '../platform/platform-ops.service';
import {
  FleetHeartbeatService,
  type TenantCatalogSource,
} from './fleet-heartbeat.service';

const keys = generateKeyPairSync('ed25519');
const TENANT_ID = '11111111-2222-4333-8444-555555555555';
const DEPLOYMENT_ID = '99999999-8888-4777-8666-555555555555';

function service(
  env: Record<string, unknown>,
  opsOverride: Partial<Record<keyof PlatformOpsService, unknown>> = {},
  catalog?: TenantCatalogSource,
) {
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
  const ops = {
    openbaoSealed: () => Promise.resolve(false),
    expiries: () =>
      Promise.resolve([
        { kind: 'tool_credential', notAfter: '2026-11-08T00:00:00.000Z' },
      ]),
    auditChain: () =>
      Promise.resolve({
        status: 'ok',
        tenantsChecked: 1,
        tenantsBroken: 0,
        verifiedAt: '2026-10-09T08:00:00.000Z',
      }),
    usageMonths: () => Promise.resolve([{ month: '2026-10', decisions: 1200 }]),
    killSwitchState: () =>
      Promise.resolve({ active: false, activatedAt: null }),
    ...opsOverride,
  } as unknown as PlatformOpsService;
  return new FleetHeartbeatService(
    config,
    readiness,
    control,
    tenants,
    kv,
    ops,
    catalog,
  );
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
      'auditChain',
      'backup',
      'counts',
      'deploymentId',
      'expiries',
      'gitSha',
      'health',
      'killSwitch',
      'nonce',
      'timestamp',
      'usage',
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
        openbaoSealed: false,
      },
      backup: {
        status: 'unknown',
        lastBackupAt: null,
        lastRestoreTestAt: null,
        lastRestoreTestStatus: null,
      },
      expiries: [
        { kind: 'tool_credential', notAfter: '2026-11-08T00:00:00.000Z' },
      ],
      auditChain: { status: 'ok', tenantsChecked: 1, tenantsBroken: 0 },
      usage: { months: [{ month: '2026-10', decisions: 1200 }] },
      killSwitch: { active: false, activatedAt: null },
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

  it('leaves out an ops section it cannot read, and still sends', async () => {
    const p = await service(
      { FLEET_DEPLOYMENT_ID: DEPLOYMENT_ID },
      {
        expiries: () => Promise.reject(new Error('openbao down')),
        auditChain: () => Promise.reject(new Error('db down')),
      },
    ).payload();
    expect(p.expiries).toBeUndefined();
    expect(p.auditChain).toBeUndefined();
    expect(p.usage).toBeDefined();
  });

  it('validates before signing: a field outside the schema is never sent', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch');
    const s = service(
      { FLEET_DEPLOYMENT_ID: DEPLOYMENT_ID },
      {
        expiries: () =>
          Promise.resolve([
            {
              kind: 'tool_credential',
              notAfter: '2026-11-08T00:00:00.000Z',
              name: 'acme-graph',
            },
          ]),
      },
    );
    await expect(s.payload()).rejects.toThrow();
    expect(await s.send('http://fleet.internal/heartbeats')).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('adds one catalog section per ACTIVE tenant: config and counts only, never a reference', async () => {
    const catalog: TenantCatalogSource = {
      view: () =>
        Promise.resolve({
          features: {
            assistant: true,
            watcher: true,
            packs: true,
            llm_proxy: false,
          },
          packs: [{ id: 'soc', version: 2, enabled: true }],
          model: {
            provider: 'azure_openai',
            model: 'gpt-5-mini',
            uaeResidency: true,
            monthlyTokenQuota: null,
          },
          usage: { month: '2026-10', tokens: 900 },
          connectors: [
            Object.assign(
              {
                name: 'microsoft-graph',
                type: 'IAM',
                protocol: 'MICROSOFT',
                enabled: true,
                credentialExpiresAt: new Date('2026-11-08T00:00:00Z'),
              },
              {
                credentialReference: {
                  provider: 'OPENBAO',
                  reference: 'tools/x',
                },
              },
            ),
          ],
        }),
    };
    const p = await service(
      { FLEET_DEPLOYMENT_ID: DEPLOYMENT_ID },
      {},
      catalog,
    ).payload();
    expect(p.tenants).toEqual([
      {
        tenantId: TENANT_ID,
        catalog: {
          features: {
            assistant: true,
            watcher: true,
            packs: true,
            llm_proxy: false,
          },
          packs: [{ id: 'soc', version: 2, enabled: true }],
          model: {
            provider: 'azure_openai',
            model: 'gpt-5-mini',
            uaeResidency: true,
            monthlyTokenQuota: null,
          },
        },
        llmTokensMonth: { month: '2026-10', tokens: 900 },
        connectors: [
          {
            name: 'microsoft-graph',
            type: 'IAM',
            protocol: 'MICROSOFT',
            enabled: true,
            credentialExpiresAt: '2026-11-08T00:00:00.000Z',
          },
        ],
      },
    ]);
    expect(JSON.stringify(p)).not.toContain('tools/x');
  });

  it('leaves out a tenant whose catalog cannot be read, and still sends', async () => {
    const p = await service(
      { FLEET_DEPLOYMENT_ID: DEPLOYMENT_ID },
      {},
      { view: () => Promise.reject(new Error('catalog store down')) },
    ).payload();
    expect(p.tenants).toEqual([]);
    expect(p.counts).toBeDefined();
  });

  it('without a catalog source, the section is absent', async () => {
    const p = await service({ FLEET_DEPLOYMENT_ID: DEPLOYMENT_ID }).payload();
    expect(p.tenants).toBeUndefined();
  });

  it('carries the restore drill duration from the backup file', async () => {
    const file = join(await mkdtemp(join(tmpdir(), 'hb-')), 'backup.json');
    await writeFile(
      file,
      JSON.stringify({
        status: 'ok',
        lastBackupAt: '2026-10-09T01:00:00Z',
        lastRestoreTestAt: '2026-10-01T09:00:00Z',
        lastRestoreTestStatus: 'ok',
        lastRestoreTestSeconds: 1260,
      }),
    );
    const p = await service({
      FLEET_DEPLOYMENT_ID: DEPLOYMENT_ID,
      FLEET_BACKUP_STATUS_FILE: file,
    }).payload();
    expect(p.backup).toMatchObject({
      lastRestoreTestStatus: 'ok',
      lastRestoreTestSeconds: 1260,
    });
  });
});
