import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { HostApprovalsService } from '../approvals/host-approvals.service';
import type { HostContext } from '../host-mtls/host-context';
import { JailHostController } from './jail-host.controller';
import {
  jailFlags,
  normalizeAskedSite,
  normalizeRuleSite,
  ruleLive,
} from './jail-sites';
import { JailSitesService } from './jail-sites.service';

const HOST: HostContext = {
  hostId: 'h1',
  tenantId: 't1',
  machineId: 'm1',
  ownerSubject: 'sub1',
  status: 'APPROVED',
};

type Rule = {
  hostId: string;
  toolId: string;
  site: string;
  mode: string;
  expiresAt: Date | null;
};

function world() {
  const rules: Rule[] = [];
  const audit: unknown[] = [];
  const approvalRows: Record<string, unknown>[] = [
    {
      id: 'ap1',
      hostId: 'h1',
      toolId: 'host.claude-code',
      actionId: 'site.connect',
      resource: 'example.org',
      status: 'PENDING',
      expiresAt: new Date(Date.now() + 60_000),
    },
    {
      id: 'ap2',
      hostId: 'h1',
      toolId: 'host.claude-code',
      actionId: 'file.read',
      resource: '/x',
      status: 'PENDING',
      expiresAt: new Date(Date.now() + 60_000),
    },
  ];
  const ruleApi = {
    findUnique: ({
      where,
    }: {
      where: { hostId_toolId_site: Omit<Rule, 'mode' | 'expiresAt'> };
    }) => {
      const k = where.hostId_toolId_site;
      return Promise.resolve(
        rules.find(
          (r) =>
            r.hostId === k.hostId && r.toolId === k.toolId && r.site === k.site,
        ) ?? null,
      );
    },
    upsert: ({
      where,
      create,
      update,
    }: {
      where: { hostId_toolId_site: Omit<Rule, 'mode' | 'expiresAt'> };
      create: Rule;
      update: Partial<Rule>;
    }) => {
      const k = where.hostId_toolId_site;
      const ex = rules.find(
        (r) =>
          r.hostId === k.hostId && r.toolId === k.toolId && r.site === k.site,
      );
      if (ex) Object.assign(ex, update);
      else rules.push({ ...create });
      return Promise.resolve({ id: 'r1', ...(ex ?? create) });
    },
    findMany: () =>
      Promise.resolve(
        rules.filter((r) => !r.expiresAt || r.expiresAt > new Date()),
      ),
  };
  const client: Record<string, unknown> = {
    hostSiteRule: ruleApi,
    hostTool: {
      findMany: () => Promise.resolve([{ toolId: 'host.claude-code' }]),
    },
    approvalAllowGrant: { create: () => Promise.resolve({ id: 'g1' }) },
    hostApproval: {
      findUnique: ({ where }: { where: { id: string } }) =>
        Promise.resolve(approvalRows.find((r) => r.id === where.id) ?? null),
      findFirst: () => Promise.resolve(null),
      count: () => Promise.resolve(0),
      create: ({ data }: { data: Record<string, unknown> }) => {
        const r = { id: 'new', status: 'PENDING', ...data };
        approvalRows.push(r);
        return Promise.resolve(r);
      },
      updateMany: () => Promise.resolve({ count: 1 }),
    },
    $transaction: (fn: (tx: unknown) => unknown) => fn(client),
  };
  const auditSvc = {
    recordSafely: (_c: unknown, _t: string, e: { eventType: string }) => {
      audit.push(e);
      return Promise.resolve({});
    },
  };
  const tenants = { getClient: () => Promise.resolve(client) };
  const push = { notifyApprovers: vi.fn() };
  const approvals = new HostApprovalsService(auditSvc as never, push as never);
  const sites = new JailSitesService(tenants as never, auditSvc as never);
  const ctrl = new JailHostController(sites, approvals, tenants as never);
  return { rules, audit, client, approvals, sites, ctrl };
}

describe('site names', () => {
  it('normalises what a device asks about', () => {
    expect(normalizeAskedSite(' Example.ORG. ')).toBe('example.org');
    expect(normalizeAskedSite('10.0.0.5')).toBe('10.0.0.5');
    expect(normalizeAskedSite('2001:db8::1')).toBe('2001:db8::1');
    expect(normalizeAskedSite('mybox')).toBe('mybox');
    expect(normalizeAskedSite('a b.com')).toBeNull();
    expect(normalizeAskedSite('*.example.org')).toBeNull();
    expect(normalizeAskedSite('x/y.com')).toBeNull();
    expect(normalizeAskedSite('')).toBeNull();
  });
  it('lets a person type a wildcard only for a public name', () => {
    expect(normalizeRuleSite('*.example.org')).toBe('*.example.org');
    expect(normalizeRuleSite('*.com')).toBeNull();
    expect(normalizeRuleSite('*.co.uk')).toBeNull();
    expect(normalizeRuleSite('*.github.io')).toBeNull();
    expect(normalizeRuleSite('Example.org')).toBe('example.org');
  });
  it('knows when a rule is live', () => {
    const now = new Date();
    expect(ruleLive({ expiresAt: null }, now)).toBe(true);
    expect(ruleLive({ expiresAt: new Date(+now + 1000) }, now)).toBe(true);
    expect(ruleLive({ expiresAt: new Date(+now - 1000) }, now)).toBe(false);
  });
  it('is on by default and Windows is off', () => {
    expect(jailFlags({})).toEqual({ enabled: true, windows: false });
    expect(jailFlags({ MANAR_JAIL_ENABLED: 'false' }).enabled).toBe(false);
    expect(jailFlags({ MANAR_JAIL_WINDOWS: 'true' }).windows).toBe(true);
  });
});

describe('POST /host/v1/jail/ask', () => {
  it('opens a prompt for a new site', async () => {
    const w = world();
    const r = await w.ctrl.ask(HOST, {
      toolId: 'host.claude-code',
      site: 'Evil.example.',
    });
    expect(r).toMatchObject({ decision: 'ask', id: 'new' });
  });
  it('answers from a remembered rule without a prompt', async () => {
    const w = world();
    w.rules.push({
      hostId: 'h1',
      toolId: 'host.claude-code',
      site: 'a.example',
      mode: 'ALLOW',
      expiresAt: null,
    });
    w.rules.push({
      hostId: 'h1',
      toolId: 'host.claude-code',
      site: 'b.example',
      mode: 'DENY',
      expiresAt: null,
    });
    expect(
      await w.ctrl.ask(HOST, { toolId: 'host.claude-code', site: 'a.example' }),
    ).toEqual({ decision: 'allow' });
    expect(
      await w.ctrl.ask(HOST, { toolId: 'host.claude-code', site: 'b.example' }),
    ).toEqual({ decision: 'deny' });
  });
  it('ignores an expired rule and another tool rule', async () => {
    const w = world();
    w.rules.push({
      hostId: 'h1',
      toolId: 'host.claude-code',
      site: 'a.example',
      mode: 'ALLOW',
      expiresAt: new Date(Date.now() - 1000),
    });
    w.rules.push({
      hostId: 'h1',
      toolId: 'host.codex-cli',
      site: 'c.example',
      mode: 'ALLOW',
      expiresAt: null,
    });
    expect(
      (
        await w.ctrl.ask(HOST, {
          toolId: 'host.claude-code',
          site: 'a.example',
        })
      ).decision,
    ).toBe('ask');
    expect(
      (
        await w.ctrl.ask(HOST, {
          toolId: 'host.claude-code',
          site: 'c.example',
        })
      ).decision,
    ).toBe('ask');
  });
  it('refuses a pending device, an unfiltered tool and a bad site', async () => {
    const w = world();
    await expect(
      w.ctrl.ask(
        { ...HOST, status: 'PENDING' },
        { toolId: 'host.claude-code', site: 'a.b' },
      ),
    ).rejects.toBeInstanceOf(ForbiddenException);
    await expect(
      w.ctrl.ask(HOST, { toolId: 'host.cursor', site: 'a.b' }),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(
      w.ctrl.ask(HOST, { toolId: 'host.claude-code', site: 'a b' }),
    ).rejects.toBeInstanceOf(BadRequestException);
  });
});

describe('deciding a new-site prompt', () => {
  const base = { approvalId: 'ap1', hostId: 'h1', subject: 'sub1' };
  it('remembers 8 hours and always for that device and tool', async () => {
    const w = world();
    await w.approvals.decide(w.client as never, 't1', {
      ...base,
      decision: 'approve_8h',
      via: 'console',
    });
    expect(w.rules).toHaveLength(1);
    expect(w.rules[0]).toMatchObject({ site: 'example.org', mode: 'ALLOW' });
    const exp = w.rules[0]!.expiresAt!.getTime() - Date.now();
    expect(exp).toBeGreaterThan(7.9 * 3_600_000);
    expect(exp).toBeLessThanOrEqual(8 * 3_600_000);
    await w.approvals.decide(w.client as never, 't1', {
      ...base,
      decision: 'approve_always',
      via: 'console',
    });
    expect(w.rules).toHaveLength(1);
    expect(w.rules[0]!.expiresAt).toBeNull();
    expect(
      w.audit.some(
        (e) =>
          (e as { eventType: string }).eventType === 'jail.site_rule.created',
      ),
    ).toBe(true);
  });
  it('remembers nothing for once or deny', async () => {
    const w = world();
    await w.approvals.decide(w.client as never, 't1', {
      ...base,
      decision: 'approve_once',
      via: 'console',
    });
    await w.approvals.decide(w.client as never, 't1', {
      ...base,
      decision: 'deny',
      via: 'console',
    });
    expect(w.rules).toHaveLength(0);
  });
  it('never takes always or 8 hours from the device', async () => {
    const w = world();
    for (const decision of ['approve_always', 'approve_8h'] as const)
      await expect(
        w.approvals.decide(w.client as never, 't1', {
          ...base,
          decision,
          via: 'device',
        }),
      ).rejects.toBeInstanceOf(ForbiddenException);
    expect(w.rules).toHaveLength(0);
  });
  it('allows always for a site prompt only', async () => {
    const w = world();
    await expect(
      w.approvals.decide(w.client as never, 't1', {
        approvalId: 'ap2',
        hostId: 'h1',
        subject: 's',
        decision: 'approve_always',
        via: 'console',
      }),
    ).rejects.toBeInstanceOf(BadRequestException);
  });
});

describe('GET /host/v1/config jail key', () => {
  it('lists the filtered tools and live rules', async () => {
    const w = world();
    w.rules.push({
      hostId: 'h1',
      toolId: 'host.claude-code',
      site: 'a.example',
      mode: 'ALLOW',
      expiresAt: null,
    });
    const c = await w.sites.config(HOST);
    expect(c).toMatchObject({
      enabled: true,
      windows: false,
      tools: ['host.claude-code'],
    });
    expect(c.rules).toHaveLength(1);
  });
});
