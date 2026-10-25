import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Logger } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AppConfig } from '../config/env.validation';
import type { ControlPrismaService } from '../database/control-prisma.service';
import type { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { registry } from '../metrics/metrics';
import { NOW, payload, signLicense, testKeys } from './license.fakes';
import { LicenseService } from './license.service';

const k = testKeys();

function service(
  env: Partial<AppConfig>,
  opts: { agents?: number; controlDown?: boolean; tenantDown?: string } = {},
) {
  const config = {
    get: (key: keyof AppConfig) =>
      ({ MANAR_DEPLOYMENT: 'customer', ...env })[key as string],
  } as unknown as ConfigService<AppConfig, true>;
  const control = {
    tenant: {
      findMany: opts.controlDown
        ? () => Promise.reject(new Error('down'))
        : () => Promise.resolve([{ id: 't1' }, { id: 't2' }]),
    },
  } as unknown as ControlPrismaService;
  const tenants = {
    getClient: (id: string) =>
      id === opts.tenantDown
        ? Promise.reject(new Error('down'))
        : Promise.resolve({
            agent: { count: () => Promise.resolve(opts.agents ?? 2) },
          }),
  } as unknown as TenantDatabaseManager;
  return new LicenseService(config, control, tenants, k.dir);
}

async function gauge(name: string, labels: Record<string, string> = {}) {
  const m = await registry.getSingleMetric(name)?.get();
  return m?.values.find((v) =>
    Object.entries(labels).every(([key, val]) => v.labels[key] === val),
  )?.value;
}

const token = (over = {}) =>
  signLicense(
    payload({ limits: { agents: 10, tenants: 5 }, ...over }),
    k.privateKey,
    k.kid,
  );

describe('LicenseService', () => {
  // Licence times in the fakes are relative to NOW.
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(NOW);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('counts ACTIVE agents across ACTIVE tenants and reports over_limit (soft: just a status)', async () => {
    const jws = token({ limits: { agents: 10, tenants: 1 } });
    const s = await service({ MANAR_LICENSE: jws }, { agents: 6 }).refresh();
    expect(s.usage).toEqual({ agents: 12, tenants: 2 });
    expect(s.status).toBe('over_limit');
    expect(s.overLimit).toEqual(['agents', 'tenants']);
  });

  it('sets the Prometheus gauges', async () => {
    const exp = payload().exp;
    await service({
      MANAR_LICENSE: token({ limits: { agents: 10, tenants: null } }),
    }).refresh();
    expect(await gauge('manar_license_status', { status: 'valid' })).toBe(1);
    expect(await gauge('manar_license_status', { status: 'missing' })).toBe(0);
    expect(await gauge('manar_license_expiry_timestamp_seconds')).toBe(exp);
    expect(await gauge('manar_license_limit', { resource: 'agents' })).toBe(10);
    // Unlimited: no limit series at all, so no alert can compare usage with 0.
    expect(
      await gauge('manar_license_limit', { resource: 'tenants' }),
    ).toBeUndefined();
    expect(await gauge('manar_license_usage', { resource: 'agents' })).toBe(4);
  });

  it('reads MANAR_LICENSE_FILE in preference to MANAR_LICENSE, and re-reads it on refresh', async () => {
    const file = join(k.dir, 'licence.jws');
    writeFileSync(file, `${token()}\n`);
    const svc = service({ MANAR_LICENSE_FILE: file, MANAR_LICENSE: 'garbage' });
    expect((await svc.refresh()).status).toBe('valid');
    writeFileSync(file, token({ exp: payload().iat }));
    expect((await svc.refresh()).status).toBe('expired');
  });

  it('an unreadable licence file is missing with a reason, never a throw', async () => {
    const s = await service({
      MANAR_LICENSE_FILE: '/nonexistent/licence',
    }).refresh();
    expect(s).toMatchObject({ status: 'missing', reason: 'file_unreadable' });
  });

  it('an unreachable control database leaves usage unknown and no limit exceeded', async () => {
    const s = await service(
      { MANAR_LICENSE: token() },
      { controlDown: true },
    ).refresh();
    expect(s.usage).toEqual({ agents: null, tenants: null });
    expect(s.status).toBe('valid');
    expect(
      await gauge('manar_license_usage', { resource: 'agents' }),
    ).toBeUndefined();
  });

  it('skips an unreachable tenant database (counts can only be low)', async () => {
    const s = await service(
      { MANAR_LICENSE: token() },
      { tenantDown: 't1' },
    ).refresh();
    expect(s.usage).toEqual({ agents: 2, tenants: 2 });
  });

  it('logs one structured warning per status change, without the licence itself', async () => {
    const warn = vi
      .spyOn(Logger.prototype, 'warn')
      .mockImplementation(() => undefined);
    const jws = token({ exp: payload().iat });
    const svc = service({ MANAR_LICENSE: jws });
    await svc.refresh();
    await svc.refresh();
    expect(warn).toHaveBeenCalledTimes(1);
    const entry = warn.mock.calls[0]![0] as Record<string, unknown>;
    expect(entry).toMatchObject({
      event: 'license_status_changed',
      status: 'expired',
      previous: null,
      licenseId: 'LIC-TEST-1',
    });
    expect(JSON.stringify(entry)).not.toContain(jws.split('.')[2]);
  });

  it('status() computes once and then serves the last result', async () => {
    const svc = service({});
    const spy = vi.spyOn(svc, 'refresh');
    expect((await svc.status()).status).toBe('missing');
    await svc.status();
    expect(spy).toHaveBeenCalledTimes(1);
  });
});
