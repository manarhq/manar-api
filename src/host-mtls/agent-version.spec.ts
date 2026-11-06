import { describe, expect, it, vi } from 'vitest';
import { registry } from '../metrics/metrics';
import { HostConfigController } from './host-config.controller';
import { agentVersionChanged, parseAgentUserAgent } from './agent-version';
import type { HostContext } from './host-context';
import { HostsAdminService } from '../hosts/hosts-admin.service';

const host: HostContext = {
  hostId: 'h1',
  tenantId: 't1',
  machineId: 'm1',
  ownerSubject: null,
  status: 'APPROVED',
  agentVersion: null,
  agentOs: null,
  agentArch: null,
};

function controller(update = vi.fn().mockResolvedValue({})) {
  const c = Object.assign(Object.create(HostConfigController.prototype), {
    tenants: { getClient: vi.fn().mockResolvedValue({ host: { update } }) },
    logger: { warn: vi.fn() },
  }) as HostConfigController;
  return { c, update };
}
const record = (c: object, h: HostContext, ua?: string) =>
  (
    c as unknown as {
      recordAgentVersion(h: HostContext, ua?: string): Promise<void>;
    }
  ).recordAgentVersion(h, ua);

const seen = async (version: string) =>
  (await registry.getMetricsAsJSON())
    .find((m) => m.name === 'manar_host_version_seen_total')!
    .values.filter((v) => v.labels['version'] === version);

describe('agent version', () => {
  it('parses only the device User-Agent', () => {
    expect(parseAgentUserAgent('manar-edge/1.2.3 (linux; amd64)')).toEqual({
      version: '1.2.3',
      os: 'linux',
      arch: 'amd64',
    });
    expect(parseAgentUserAgent('Go-http-client/1.1')).toBeNull();
    expect(parseAgentUserAgent(undefined)).toBeNull();
  });

  it('notices a change and nothing else', () => {
    const s = { version: '1.0.0', os: 'linux', arch: 'amd64' };
    expect(agentVersionChanged(s, {})).toBe(true);
    expect(
      agentVersionChanged(s, {
        agentVersion: '1.0.0',
        agentOs: 'linux',
        agentArch: 'amd64',
      }),
    ).toBe(false);
    expect(
      agentVersionChanged(s, {
        agentVersion: '0.9.0',
        agentOs: 'linux',
        agentArch: 'amd64',
      }),
    ).toBe(true);
  });

  it('writes the first report, counts it, and stays quiet while it is unchanged', async () => {
    const { c, update } = controller();
    await record(c, host, 'manar-edge/7.7.7 (linux; amd64)');
    expect(update).toHaveBeenCalledTimes(1);
    expect(update.mock.calls[0]![0]).toMatchObject({
      where: { id: 'h1' },
      data: { agentVersion: '7.7.7', agentOs: 'linux', agentArch: 'amd64' },
    });
    expect((await seen('7.7.7'))[0]!.value).toBe(1);
    await record(
      c,
      { ...host, agentVersion: '7.7.7', agentOs: 'linux', agentArch: 'amd64' },
      'manar-edge/7.7.7 (linux; amd64)',
    );
    expect(update).toHaveBeenCalledTimes(1);
  });

  it('keeps old agents working: no header, no write, no failure', async () => {
    const { c, update } = controller();
    await record(c, host, 'Go-http-client/1.1');
    await record(c, host, undefined);
    expect(update).not.toHaveBeenCalled();
  });

  it('never fails the config poll when the write fails', async () => {
    const { c } = controller(vi.fn().mockRejectedValue(new Error('db down')));
    await expect(
      record(c, host, 'manar-edge/8.8.8 (windows; arm64)'),
    ).resolves.toBeUndefined();
  });

  it('bounds the version labels a device can create', async () => {
    const { c } = controller();
    for (let i = 0; i < 80; i++)
      await record(c, host, `manar-edge/9.${i}.0 (linux; amd64)`);
    const m = (await registry.getMetricsAsJSON()).find(
      (x) => x.name === 'manar_host_version_seen_total',
    )!;
    expect(new Set(m.values.map((v) => v.labels['version'])).size).toBeLessThan(
      60,
    );
  });
});

describe('hosts API', () => {
  it('lists the last seen version, OS and architecture of each host', async () => {
    const row = {
      id: 'h1',
      createdAt: new Date('2026-11-05T00:00:00Z'),
      agentVersion: '1.2.3',
      agentOs: 'linux',
      agentArch: 'amd64',
      agentVersionSeenAt: new Date('2026-11-05T09:00:00Z'),
    };
    const client = {
      host: { findMany: vi.fn().mockResolvedValue([row]) },
      secretEvent: { findMany: vi.fn().mockResolvedValue([]) },
    };
    const admin = Object.create(
      HostsAdminService.prototype,
    ) as HostsAdminService;
    const page = await admin.listHosts(client as never, { limit: 10 });
    expect(page.items[0]).toMatchObject({
      agentVersion: '1.2.3',
      agentOs: 'linux',
      agentArch: 'amd64',
    });
  });
});
