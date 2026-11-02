import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { HostApprovalsService } from '../approvals/host-approvals.service';
import type { HostContext } from '../host-mtls/host-context';
import { HostApprovalsController } from '../approvals/host-approvals.controller';
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
  source?: string;
  expiresAt: Date | null;
};

const osLabel = { value: 'Ubuntu 24.04 (linux)' };
const extraCount = { value: 0 };

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
    findMany: ({
      where,
      orderBy,
      take,
    }: {
      where?: { hostId?: string; toolId?: string; mode?: string };
      orderBy?: { createdAt: string };
      take?: number;
    } = {}) =>
      Promise.resolve(
        (orderBy?.createdAt === 'desc' ? [...rules].reverse() : rules)
          .filter(
            (r) =>
              (!where?.hostId || r.hostId === where.hostId) &&
              (!where?.toolId || r.toolId === where.toolId) &&
              (!where?.mode || r.mode === where.mode),
          )
          .slice(0, take ?? Infinity),
      ),
  };
  const client: Record<string, unknown> = {
    host: { findUnique: () => Promise.resolve({ os: osLabel.value }) },
    hostSiteRule: ruleApi,
    hostTool: {
      findMany: ({ where }: { where: { toolId: { in: string[] } } }) =>
        Promise.resolve(
          ['host.claude-code', 'host.codex-cli']
            .filter((t) => where.toolId.in.includes(t))
            .map((toolId) => ({ toolId })),
        ),
    },
    approvalAllowGrant: { create: () => Promise.resolve({ id: 'g1' }) },
    hostApproval: {
      findUnique: ({ where }: { where: { id: string } }) =>
        Promise.resolve(approvalRows.find((r) => r.id === where.id) ?? null),
      findFirst: () => Promise.resolve(null),
      findMany: ({ where }: { where: { hostId?: string } }) =>
        Promise.resolve(
          approvalRows.filter(
            (r) =>
              r.status === 'PENDING' &&
              (!where.hostId || r.hostId === where.hostId),
          ),
        ),
      count: ({
        where,
      }: {
        where: {
          toolId?: string;
          status?: string;
          actionId?: string | { not: string };
        };
      }) =>
        Promise.resolve(
          approvalRows.filter((r) => {
            const a = where.actionId;
            if (typeof a === 'string' && r.actionId !== a) return false;
            if (a && typeof a === 'object' && r.actionId === a.not)
              return false;
            if (where.toolId && r.toolId !== where.toolId) return false;
            if (where.status && r.status !== where.status) return false;
            return true;
          }).length + extraCount.value,
        ),
      create: ({ data }: { data: Record<string, unknown> }) => {
        const r = { id: 'new', status: 'PENDING', ...data };
        approvalRows.push(r);
        return Promise.resolve(r);
      },
      updateMany: () => Promise.resolve({ count: 1 }),
    },
    // warden2: approvals read the database clock and the workspace pause.
    $queryRaw: () => Promise.resolve([{ now: new Date() }]),
    workspacePause: { findUnique: () => Promise.resolve(null) },
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
  // Every decider here is an approver (who may decide is covered in host-approvals.spec.ts).
  const approvers = {
    deciderKind: () => Promise.resolve('admin'),
    canApprove: () => Promise.resolve(true),
  };
  const approvals = new HostApprovalsService(
    auditSvc as never,
    push as never,
    approvers as never,
  );
  const sites = new JailSitesService(tenants as never, auditSvc as never);
  const ctrl = new JailHostController(sites, approvals, tenants as never);
  return { rules, audit, approvalRows, client, approvals, sites, ctrl };
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
  it('is on by default, Windows included', () => {
    expect(jailFlags({})).toEqual({ enabled: true, windows: true });
    expect(jailFlags({ MANAR_JAIL_ENABLED: 'false' }).enabled).toBe(false);
    expect(jailFlags({ MANAR_JAIL_WINDOWS: 'false' }).windows).toBe(false);
  });
});

describe('POST /host/v1/jail/ask', () => {
  it('opens a prompt for a new site', async () => {
    const w = world();
    const r = await w.ctrl.ask(HOST, {
      toolId: 'host.claude-code',
      site: 'Evil.example.',
    });
    expect(r).toMatchObject({ decision: 'ask' });
    // The approval id is a fresh uuid (phone match codes are derived from it).
    expect(r).toHaveProperty('id', w.approvalRows.at(-1)?.id);
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
      canWriteSiteRules: true,
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
      canWriteSiteRules: true,
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

describe("an approval never overrides a person's rule", () => {
  const base = { approvalId: 'ap1', hostId: 'h1', subject: 'sub1' };
  const rule = (over: Partial<Rule>): Rule => ({
    hostId: 'h1',
    toolId: 'host.claude-code',
    site: 'example.org',
    mode: 'DENY',
    source: 'console',
    expiresAt: null,
    ...over,
  });
  it('keeps an exact DENY and applies once only', async () => {
    const w = world();
    w.rules.push(rule({}));
    const r = await w.approvals.decide(w.client as never, 't1', {
      ...base,
      decision: 'approve_always',
      via: 'console',
      canWriteSiteRules: true,
    });
    expect(w.rules).toEqual([rule({})]);
    expect(r).toMatchObject({
      decision: 'approve_once',
      remembered: false,
      note: 'site_rule_exists',
    });
  });
  it('keeps a wildcard DENY', async () => {
    const w = world();
    w.rules.push(rule({ site: '*.example.org' }));
    w.approvalRows[0]!.resource = 'a.example.org';
    await w.approvals.decide(w.client as never, 't1', {
      ...base,
      decision: 'approve_8h',
      via: 'console',
      canWriteSiteRules: true,
    });
    expect(w.rules).toHaveLength(1);
    expect(w.rules[0]!.mode).toBe('DENY');
  });
  it('keeps a console ALLOW and its expiry', async () => {
    const w = world();
    const mine = rule({ mode: 'ALLOW', expiresAt: null });
    w.rules.push(mine);
    const r = await w.approvals.decide(w.client as never, 't1', {
      ...base,
      decision: 'approve_8h',
      via: 'console',
      canWriteSiteRules: true,
    });
    expect(w.rules).toEqual([mine]);
    expect(r.remembered).toBe(false);
  });
  it('overwrites its own earlier approval rule', async () => {
    const w = world();
    w.rules.push(
      rule({
        mode: 'ALLOW',
        source: 'approval',
        expiresAt: new Date(Date.now() + 60_000),
      }),
    );
    const r = await w.approvals.decide(w.client as never, 't1', {
      ...base,
      decision: 'approve_always',
      via: 'console',
      canWriteSiteRules: true,
    });
    expect(r.remembered).toBe(true);
    expect(w.rules[0]!.expiresAt).toBeNull();
  });
  it('gives an approver without the site-rule role "once" for always', async () => {
    const w = world();
    const r = await w.approvals.decide(w.client as never, 't1', {
      ...base,
      decision: 'approve_always',
      via: 'console',
    });
    expect(w.rules).toHaveLength(0);
    expect(r).toMatchObject({
      decision: 'approve_once',
      remembered: false,
      note: 'needs_owner',
    });
  });
  it('gives that approver "once" for 8 hours too', async () => {
    const w = world();
    const r = await w.approvals.decide(w.client as never, 't1', {
      ...base,
      decision: 'approve_8h',
      via: 'console',
    });
    expect(r).toMatchObject({
      decision: 'approve_once',
      remembered: false,
      note: 'needs_owner',
    });
    expect(w.rules).toHaveLength(0);
  });
  it('answers an ask from an exact or wildcard DENY without opening a prompt', async () => {
    const w = world();
    w.rules.push(rule({ site: '*.example.org' }));
    const before = w.approvalRows.length;
    expect(
      await w.ctrl.ask(HOST, {
        toolId: 'host.claude-code',
        site: 'a.example.org',
      }),
    ).toEqual({ decision: 'deny' });
    w.rules.push(rule({ site: 'evil.test', mode: 'DENY' }));
    expect(
      await w.ctrl.ask(HOST, { toolId: 'host.claude-code', site: 'evil.test' }),
    ).toEqual({ decision: 'deny' });
    expect(w.approvalRows.length).toBe(before);
  });
  it('lets a DENY beat an ALLOW for the same site', async () => {
    const w = world();
    w.rules.push(rule({ site: '*.example.org', mode: 'ALLOW' }));
    w.rules.push(rule({ site: 'bad.example.org', mode: 'DENY' }));
    expect(
      await w.ctrl.ask(HOST, {
        toolId: 'host.claude-code',
        site: 'bad.example.org',
      }),
    ).toEqual({ decision: 'deny' });
    expect(
      await w.ctrl.ask(HOST, {
        toolId: 'host.claude-code',
        site: 'ok.example.org',
      }),
    ).toEqual({ decision: 'allow' });
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
      windows: true,
      tools: ['host.claude-code', 'host.codex-cli'],
    });
    expect(c.rules).toHaveLength(1);
  });
});

describe('jail key by operating system', () => {
  afterEach(() => {
    delete process.env.MANAR_JAIL_WINDOWS;
    osLabel.value = 'Ubuntu 24.04 (linux)';
  });
  it('gives Linux both CLI tools it has', async () => {
    const w = world();
    expect((await w.sites.config(HOST)).tools).toEqual([
      'host.claude-code',
      'host.codex-cli',
    ]);
  });
  it('filters nothing on Windows while the Windows switch is off', async () => {
    osLabel.value = 'Windows 11 Pro';
    process.env.MANAR_JAIL_WINDOWS = 'false';
    const c = await world().sites.config(HOST);
    expect(c).toMatchObject({ enabled: true, windows: false, tools: [] });
  });
  it('filters only Claude Code on Windows by default', async () => {
    osLabel.value = 'Windows 11 Pro';
    const c = await world().sites.config(HOST);
    expect(c).toMatchObject({ windows: true, tools: ['host.claude-code'] });
  });
});

describe('site prompts are answered in the console or on the phone', () => {
  const base = { approvalId: 'ap1', hostId: 'h1', subject: 'sub1' };
  it('refuses once and the longer answers from the device but accepts a withdrawal', async () => {
    const w = world();
    for (const decision of [
      'approve_once',
      'approve_8h',
      'approve_always',
    ] as const)
      await expect(
        w.approvals.decide(w.client as never, 't1', {
          ...base,
          decision,
          via: 'device',
        }),
      ).rejects.toBeInstanceOf(ForbiddenException);
    await expect(
      w.approvals.decide(w.client as never, 't1', {
        ...base,
        decision: 'deny',
        via: 'device',
      }),
    ).resolves.toMatchObject({ status: 'EXPIRED' }); // withdrawn: nobody denied it
  });
  it('is not shown to the desktop as something it can decide', async () => {
    const w = world();
    const ctrl = new HostApprovalsController(
      w.approvals,
      { getClient: () => Promise.resolve(w.client) } as never,
      { deciderKind: () => Promise.resolve('admin') } as never,
    );
    const r = await ctrl.pending(HOST);
    const site = r.items.find((i) => i.actionId === 'site.connect');
    const other = r.items.find((i) => i.actionId === 'file.read');
    expect(site?.decidableHere).toBe(false);
    expect(other?.decidableHere).toBe(true);
    await expect(
      ctrl.decide(HOST, 'ap1', { decision: 'approve_once' }),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });
});

describe('asks have their own budget', () => {
  const open = (
    w: ReturnType<typeof world>,
    site: string,
    tool = 'host.claude-code',
  ) =>
    w.approvals.open(w.client as never, 't1', {
      hostId: 'h1',
      toolId: tool,
      actionId: 'site.connect',
      resource: site,
      summary: 'x',
      highRisk: false,
      toolName: 'x',
    });
  it('caps what one tool can keep waiting, without touching another tool or other prompts', async () => {
    const w = world();
    for (let i = 0; i < 9; i++) await open(w, `s${i}.example`); // ap1 already waits: 10 in all
    await expect(open(w, 'one-more.example')).rejects.toMatchObject({
      status: 429,
    });
    await expect(
      open(w, 'ok.example', 'host.codex-cli'),
    ).resolves.toBeDefined();
  });
  it('a flood of asks does not use up the budget of other prompts', async () => {
    const w = world();
    extraCount.value = 0;
    const many = Array.from({ length: 30 }, (_, i) => i);
    for (const i of many)
      w.approvalRows.push({
        id: `x${i}`,
        hostId: 'h1',
        toolId: `host.t${i % 5}`,
        actionId: 'site.connect',
        resource: `h${i}`,
        status: 'DENIED',
        expiresAt: new Date(Date.now() + 1000),
      });
    await expect(open(w, 'late.example', 'host.fresh')).rejects.toMatchObject({
      status: 429,
    });
    await expect(
      w.approvals.open(w.client as never, 't1', {
        hostId: 'h1',
        toolId: 'host.cursor',
        actionId: 'file.read',
        resource: '/x/y',
        summary: 'x',
        highRisk: false,
        toolName: 'Cursor',
      }),
    ).resolves.toBeDefined();
  });
});

describe('rules sent to the device', () => {
  it('sends every DENY and the newest ALLOW rules first', async () => {
    const w = world();
    for (let i = 0; i < 1200; i++)
      w.rules.push({
        hostId: 'h1',
        toolId: 'host.claude-code',
        site: `a${i}.example`,
        mode: 'ALLOW',
        expiresAt: null,
      });
    w.rules.push({
      hostId: 'h1',
      toolId: 'host.claude-code',
      site: 'blocked.example',
      mode: 'DENY',
      expiresAt: null,
    });
    const c = await w.sites.config(HOST);
    expect(c.rules.length).toBe(1001);
    expect(c.rules[0]).toMatchObject({ site: 'blocked.example', mode: 'DENY' });
  });
});
