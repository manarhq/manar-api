import { KillSwitchService } from '../kill-switches/kill-switch.service';
import type { KillSwitchEpochService } from '../kill-switches/kill-switch-epoch.service';
import type { PlatformKillSwitchService } from '../kill-switches/platform-kill-switch.service';
import { randomBytes } from 'node:crypto';
import {
  ExecutionContext,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { validate } from '../config/env.validation';
import { AgentEnrollController } from '../agents/agent-enroll.controller';
import type { AgentsService } from '../agents/agents.service';
import { EnrollmentTokenInvalidError } from '../agents/agents.errors';
import type { ControlPrismaService } from '../database/control-prisma.service';
import type { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { EdgeGatewayGuard } from './edge-internal.controller';
import { EgressRulesController } from './egress-rules.controller';
import type { AuthContext } from '../auth/auth-context';
import type { ModuleRef } from '@nestjs/core';
import { vi } from 'vitest';
import type { AuditService } from '../audit/audit.service';
import {
  EdgeAddressPoolExhaustedError,
  EdgeKeyInUseError,
  EdgePeerService,
} from './edge-peer.service';
import {
  gatewayIp,
  isWgPublicKey,
  nextFreeAddress,
  isPublicSuffix,
  normalizeEgressHost,
  parseCidr,
} from './edge-net';
import { edgeConfigIssues } from './edge.config';

const KEY = randomBytes(32).toString('base64');
const TOKEN = 'g'.repeat(40);

describe('edge-net', () => {
  it('parses the overlay CIDR and derives the gateway address', () => {
    const cidr = parseCidr('100.88.0.0/16')!;
    expect(gatewayIp(cidr)).toBe('100.88.0.1');
    for (const bad of [
      '100.88.0.1/16',
      '100.88.0.0',
      '300.1.1.0/24',
      '10.0.0.0/31',
      'x/8',
    ])
      expect(parseCidr(bad)).toBeNull();
  });

  it('allocates the lowest free host after the gateway, never a held one, never broadcast', () => {
    const cidr = parseCidr('10.9.0.0/30')!; // .1 gateway, .2 the only peer, .3 broadcast
    expect(nextFreeAddress(cidr, new Set())).toBe('10.9.0.2/32');
    expect(nextFreeAddress(cidr, new Set(['10.9.0.2/32']))).toBeNull();
    const wide = parseCidr('100.88.0.0/16')!;
    expect(
      nextFreeAddress(wide, new Set(['100.88.0.2/32', '100.88.0.3/32'])),
    ).toBe('100.88.0.4/32');
    expect(nextFreeAddress(wide, new Set(['100.88.0.3/32']))).toBe(
      '100.88.0.2/32',
    );
  });

  it('accepts only canonical base64 of 32 bytes as a WireGuard key', () => {
    expect(isWgPublicKey(KEY)).toBe(true);
    expect(isWgPublicKey(randomBytes(31).toString('base64'))).toBe(false);
    expect(isWgPublicKey(randomBytes(33).toString('base64'))).toBe(false);
    expect(isWgPublicKey(KEY.replace('=', ''))).toBe(false);
    expect(isWgPublicKey('not a key')).toBe(false);
  });

  it('normalizes allow-list hosts and refuses IPs, ports, paths and bare wildcards', () => {
    expect(normalizeEgressHost(' Graph.Microsoft.com ')).toBe(
      'graph.microsoft.com',
    );
    expect(normalizeEgressHost('*.github.com')).toBe('*.github.com');
    for (const bad of [
      '10.0.0.1',
      '1.2.3.4',
      'example.com:443',
      'example.com/path',
      'https://example.com',
      '*.com',
      '*',
      'a.*.com',
      'localhost',
      '-bad.com',
      `${'a'.repeat(64)}.com`,
      `${'a.'.repeat(130)}com`,
      '',
    ])
      expect(normalizeEgressHost(bad), bad).toBeNull();
  });

  it('refuses wildcards over a public suffix and special-use names', () => {
    for (const bad of [
      '*.co.uk',
      '*.github.io',
      '*.com.au',
      '*.foo.ck', // under the `*.ck` rule
      'printer.local',
      'api.internal',
      '*.svc.internal',
      'app.localhost',
      'abc.onion',
      '1.0.0.10.in-addr.arpa',
      // Not delegated by ICANN: internal and search-domain style names.
      'api.svc',
      'nas.lan',
      'git.corp',
      'router.home',
      'kube-dns.kube-system.svc.cluster.local',
      'host.example.notatld',
    ])
      expect(normalizeEgressHost(bad), bad).toBeNull();
    for (const good of [
      '*.example.co.uk',
      '*.myorg.github.io',
      'github.io', // an exact host never covers anyone else
      'co.uk',
      '*.www.ck', // `!www.ck` is an exception: not a public suffix
      'www.ck',
      'portal.gov.ae',
      'example.xn--mgbaam7a8h', // an IDN ccTLD in punycode
    ])
      expect(normalizeEgressHost(good), good).toBe(good);
    expect(isPublicSuffix('github.io')).toBe(true);
    expect(isPublicSuffix('example.com')).toBe(false);
  });
});

describe('edge config', () => {
  const base = {
    MANAR_EDGE_ENABLED: 'true' as const,
    MANAR_EDGE_CIDR: '100.88.0.0/16',
    MANAR_EDGE_ENDPOINT: 'edge.example.test:51820',
    MANAR_EDGE_GATEWAY_PUBLIC_KEY: KEY,
    MANAR_EDGE_GATEWAY_TOKEN: TOKEN,
    MANAR_AGENTS_HOST: 'agents.example.test',
  };

  it('is off by default and then needs nothing', () => {
    expect(
      edgeConfigIssues({
        ...base,
        MANAR_EDGE_ENABLED: 'false',
        MANAR_EDGE_GATEWAY_TOKEN: undefined,
      }),
    ).toEqual([]);
  });

  it('when on, requires endpoint, gateway key, a long token and the agents host', () => {
    expect(edgeConfigIssues(base)).toEqual([]);
    expect(
      edgeConfigIssues({
        ...base,
        MANAR_EDGE_ENDPOINT: undefined,
        MANAR_EDGE_GATEWAY_PUBLIC_KEY: 'x',
        MANAR_EDGE_GATEWAY_TOKEN: 'short',
        MANAR_AGENTS_HOST: undefined,
      }),
    ).toHaveLength(4);
  });

  it('stops startup on a bad CIDR', () => {
    expect(() => validate({ MANAR_EDGE_CIDR: '100.88.0.1/16' })).toThrow(
      /MANAR_EDGE_CIDR/,
    );
  });
});

function guardContext(
  authorization?: string,
  extra: Record<string, string> = {},
): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => ({ headers: { authorization, ...extra } }),
    }),
  } as unknown as ExecutionContext;
}

function config(values: Partial<AppConfig>): ConfigService<AppConfig, true> {
  return {
    get: (k: keyof AppConfig) => values[k],
  } as unknown as ConfigService<AppConfig, true>;
}

describe('EdgeGatewayGuard', () => {
  const guard = new EdgeGatewayGuard(
    config({ MANAR_EDGE_ENABLED: 'true', MANAR_EDGE_GATEWAY_TOKEN: TOKEN }),
  );

  it('admits the exact bearer token', () => {
    expect(guard.canActivate(guardContext(`Bearer ${TOKEN}`))).toBe(true);
  });

  it.each([
    undefined,
    '',
    TOKEN,
    `Bearer ${TOKEN}x`,
    `Bearer ${TOKEN.slice(1)}`,
    `Basic ${TOKEN}`,
    'Bearer ',
  ])('refuses %s with a bare 401', (header) => {
    let thrown: unknown;
    try {
      guard.canActivate(guardContext(header));
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(UnauthorizedException);
    expect((thrown as UnauthorizedException).getResponse()).toEqual({
      statusCode: 401,
      message: 'Unauthorized',
    });
  });

  it.each([
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-proto',
    'x-forwarded-port',
    'forwarded',
    'x-real-ip',
    'via',
    'cf-connecting-ip',
    'true-client-ip',
  ])(
    'answers 404 to a request that came through a proxy (%s), even with the right token',
    (name) => {
      expect(() =>
        guard.canActivate(
          guardContext(`Bearer ${TOKEN}`, { [name]: '1.2.3.4' }),
        ),
      ).toThrow(NotFoundException);
    },
  );

  it('answers 404 while the edge is off, even with the right token', () => {
    const off = new EdgeGatewayGuard(
      config({ MANAR_EDGE_ENABLED: 'false', MANAR_EDGE_GATEWAY_TOKEN: TOKEN }),
    );
    expect(() => off.canActivate(guardContext(`Bearer ${TOKEN}`))).toThrow(
      NotFoundException,
    );
  });
});

describe('POST /agents/enroll with edge', () => {
  function controller(
    enabled: boolean,
    edge: Partial<EdgePeerService> = {},
    tenant: { id: string; slug: string } | null = null,
    tokenValid = true,
  ) {
    const touched: string[] = [];
    const c = new AgentEnrollController(
      {
        verifyEnrollmentToken: () => {
          touched.push('verify');
          return Promise.resolve(tokenValid ? { agentId: 'agent-1' } : null);
        },
        enroll: () => {
          touched.push('enroll');
          if (!tokenValid)
            return Promise.reject(new EnrollmentTokenInvalidError('not_found'));
          return Promise.resolve({
            certificatePem: 'cert',
            caChainPem: 'chain',
            serialNumber: 'ab12',
            notBefore: new Date(),
            notAfter: new Date(),
            agentId: 'agent-1',
            agentSlug: 'a1',
          });
        },
        revokeEnrollmentCertificate: (...args: unknown[]) => {
          touched.push(`revoke:${String(args[3])}`);
          return Promise.resolve();
        },
      } as unknown as AgentsService,
      {
        tenant: {
          findUnique: () => {
            touched.push('tenant');
            return Promise.resolve(tenant);
          },
        },
      } as unknown as ControlPrismaService,
      {
        getClient: () => Promise.resolve({}),
      } as unknown as TenantDatabaseManager,
      { enabled, ...edge } as EdgePeerService,
    );
    return { c, touched };
  }
  const t = { id: 'tenant-1', slug: 'acme' };

  it('400 edge_not_enabled when the install has the edge off, before the token is used', async () => {
    const { c, touched } = controller(false);
    await expect(
      c.enroll({ token: 't', csr: 'c', edge: { wgPublicKey: KEY } }),
    ).rejects.toMatchObject({
      response: { statusCode: 400, code: 'edge_not_enabled' },
    });
    expect(touched).toEqual([]);
  });

  it('400 on a key that is not 32 bytes of base64, before the token is used', async () => {
    const { c, touched } = controller(true);
    await expect(
      c.enroll({ token: 't', csr: 'c', edge: { wgPublicKey: 'abc' } }),
    ).rejects.toMatchObject({ status: 400 });
    expect(touched).toEqual([]);
  });

  it("409 on another agent's key or a full address pool before the token is spent", async () => {
    const { c, touched } = controller(
      true,
      { preflight: () => Promise.reject(new EdgeKeyInUseError()) },
      t,
    );
    await expect(
      c.enroll({ token: 'acme:a1:x', csr: 'c', edge: { wgPublicKey: KEY } }),
    ).rejects.toMatchObject({ status: 409 });
    expect(touched).toEqual(['tenant', 'verify']);
  });

  it('refuses an edge request whose token does not verify with the uniform 401: no token spent, nothing signed, no edge check', async () => {
    const preflight = vi.fn();
    const { c, touched } = controller(true, { preflight }, t, false);
    await expect(
      c.enroll({ token: 'acme:a1:x', csr: 'c', edge: { wgPublicKey: KEY } }),
    ).rejects.toMatchObject({
      status: 401,
      response: { message: 'Invalid enrollment token' },
    });
    expect(preflight).not.toHaveBeenCalled();
    expect(touched).toEqual(['tenant', 'verify']);
  });

  it('revokes the just-signed certificate when the edge step fails after signing', async () => {
    const { c, touched } = controller(
      true,
      {
        preflight: () => Promise.resolve(),
        enroll: () => Promise.reject(new EdgeAddressPoolExhaustedError()),
      },
      t,
    );
    await expect(
      c.enroll({ token: 'acme:a1:x', csr: 'c', edge: { wgPublicKey: KEY } }),
    ).rejects.toMatchObject({ status: 409 });
    expect(touched).toEqual(['tenant', 'verify', 'enroll', 'revoke:ab12']);
  });
});

describe('EdgePeerService hooks', () => {
  function service(failures: number) {
    let calls = 0;
    const control = {
      edgePeer: {
        findMany: () => {
          calls++;
          return calls <= failures
            ? Promise.reject(new Error('db down'))
            : Promise.resolve([]);
        },
      },
    } as unknown as ControlPrismaService;
    const svc = new EdgePeerService(
      control,
      {} as TenantDatabaseManager,
      config({ MANAR_EDGE_ENABLED: 'false' }),
      {} as ModuleRef,
      {} as AuditService,
    );
    return { svc, calls: () => calls };
  }

  it('retries a failed refresh and succeeds without a full recompute', async () => {
    const { svc, calls } = service(2);
    const reconcile = vi.spyOn(svc, 'reconcile');
    await svc.agentChanged('t', 'a');
    expect(calls()).toBe(3);
    expect(reconcile).not.toHaveBeenCalled();
  });

  it('after three failures schedules a full recompute instead of dropping the change', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout'] });
    try {
      const { svc, calls } = service(10);
      const reconcile = vi.spyOn(svc, 'reconcile').mockResolvedValue(undefined);
      const done = svc.agentChanged('t', 'a');
      await vi.advanceTimersByTimeAsync(1_000);
      await done;
      expect(calls()).toBe(3);
      expect(reconcile).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(5_000);
      expect(reconcile).toHaveBeenCalledWith(true);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('EdgePeerService reads and timers', () => {
  it('a peer whose read hangs or fails is cut alone, the others are read, and a recompute is scheduled', async () => {
    const svc = new EdgePeerService(
      {} as ControlPrismaService,
      {
        getClient: () =>
          Promise.resolve({
            agentEgressRule: { findMany: () => Promise.resolve([]) },
            agentCertificate: {
              findFirst: () =>
                Promise.resolve({ notAfter: new Date(Date.now() + 3_600_000) }),
            },
          }),
      } as unknown as TenantDatabaseManager,
      config({ MANAR_EDGE_ENABLED: 'false' }),
      {
        get: () => ({
          checkAgent: (_db: unknown, _t: string, agentId: string) =>
            agentId === 'hangs'
              ? new Promise(() => undefined)
              : agentId === 'fails'
                ? Promise.reject(new Error('boom'))
                : Promise.resolve({ killed: false }),
        }),
      } as unknown as ModuleRef,
      {} as AuditService,
    );
    const markDirty = vi
      .spyOn(svc as unknown as { markDirty: () => void }, 'markDirty')
      .mockImplementation(() => undefined);
    const result = new Map<
      string,
      { state: string; cutReason: string | null }
    >();
    const ticket = (id: string) => ({
      id,
      tenantId: 't',
      agentId: id,
      refreshSeq: 1,
    });
    await (
      svc as unknown as {
        computeTenant: (
          t: string,
          l: unknown[],
          r: Map<string, unknown>,
        ) => Promise<void>;
      }
    ).computeTenant(
      't',
      ['hangs', 'ok-1', 'fails', 'ok-2'].map(ticket),
      result,
    );
    expect(result.get('hangs')).toMatchObject({
      state: 'cut',
      cutReason: 'enforcement_dependency_unavailable',
    });
    expect(result.get('fails')).toMatchObject({
      state: 'cut',
      cutReason: 'enforcement_dependency_unavailable',
    });
    expect(result.get('ok-1')).toMatchObject({ state: 'active' });
    expect(result.get('ok-2')).toMatchObject({ state: 'active' });
    expect(markDirty).toHaveBeenCalled();
  }, 10_000);

  it('a lost epoch bump plus a quarantine still cuts the peer: the refresh never reads the kill-switch cache', async () => {
    const state = { quarantined: false };
    const db = {
      agent: { findUnique: () => Promise.resolve({ status: 'ACTIVE' }) },
      killSwitch: { findFirst: () => Promise.resolve(null) },
      agentQuarantine: {
        findFirst: () =>
          Promise.resolve(state.quarantined ? { id: 'q' } : null),
      },
      agentGroupMembership: { findMany: () => Promise.resolve([]) },
      aiSystemAgentLink: { findMany: () => Promise.resolve([]) },
      agentEgressRule: { findMany: () => Promise.resolve([]) },
      agentCertificate: {
        findFirst: () =>
          Promise.resolve({ notAfter: new Date(Date.now() + 3_600_000) }),
      },
    };
    const killSwitches = new KillSwitchService(
      { recordSafely: vi.fn() } as unknown as AuditService,
      {
        isActive: () => Promise.resolve(false),
      } as unknown as PlatformKillSwitchService,
      undefined,
      {
        maxAgeMs: 2000,
        read: () => Promise.resolve('0:0'), // the bump was lost: the epoch never moves
      } as unknown as KillSwitchEpochService,
    );
    // Warm the cache the way a decision does.
    await killSwitches.checkAll(db as never, 't', { agentId: 'a' });
    state.quarantined = true;
    expect(
      (await killSwitches.checkAll(db as never, 't', { agentId: 'a' })).killed,
    ).toBe(false);
    const svc = new EdgePeerService(
      {} as ControlPrismaService,
      {
        getClient: () => Promise.resolve(db),
      } as unknown as TenantDatabaseManager,
      config({ MANAR_EDGE_ENABLED: 'false' }),
      { get: () => killSwitches } as unknown as ModuleRef,
      {} as AuditService,
    );
    const result = new Map<
      string,
      { state: string; cutReason: string | null }
    >();
    await (
      svc as unknown as {
        computeTenant: (
          t: string,
          l: unknown[],
          r: Map<string, unknown>,
        ) => Promise<void>;
      }
    ).computeTenant(
      't',
      [{ id: 'p', tenantId: 't', agentId: 'a', refreshSeq: 1 }],
      result,
    );
    expect(result.get('p')).toMatchObject({
      state: 'cut',
      cutReason: 'agent_quarantined',
    });
  });

  it('arms the expiry timer at boot and re-arms it after it fires', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'setInterval', 'setImmediate'] });
    try {
      const svc = new EdgePeerService(
        {
          edgePeer: {
            findFirst: () =>
              Promise.resolve({ certNotAfter: new Date(Date.now() + 1_000) }),
            findMany: () => Promise.resolve([]),
          },
        } as unknown as ControlPrismaService,
        {} as TenantDatabaseManager,
        config({ MANAR_EDGE_ENABLED: 'true' }),
        {} as ModuleRef,
        {} as AuditService,
      );
      vi.spyOn(svc, 'reconcile').mockResolvedValue(undefined);
      const schedule = vi.spyOn(
        svc as unknown as { scheduleExpiry: () => Promise<void> },
        'scheduleExpiry',
      );
      svc.onModuleInit();
      await vi.advanceTimersByTimeAsync(10);
      expect(schedule).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(1_500);
      // Fired: the expiry refresh re-arms it, and the finally re-arms it again.
      expect(schedule.mock.calls.length).toBeGreaterThanOrEqual(2);
      await svc.onModuleDestroy();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('GET /agents/:id/edge', () => {
  // Two tenants, each with its own database; t1's agent a1 has a cut peer, t2's agent a2 an
  // active one. Rows are keyed by tenant and agent like the unique index.
  const agents: Record<string, string[]> = {
    t1: ['a1', 'a3', 'same'],
    t2: ['a2', 'same'],
  };
  const rows: Record<string, object> = {
    't1/same': {
      state: 'active',
      cutReason: null,
      address: '100.88.0.4/32',
      updatedAt: new Date('2026-10-26T12:00:00Z'),
    },
    't1/a1': {
      state: 'cut',
      cutReason: 'agent_quarantined',
      address: '100.88.0.2/32',
      updatedAt: new Date('2026-10-26T10:00:00Z'),
    },
    't2/a2': {
      state: 'active',
      cutReason: null,
      address: '100.88.0.3/32',
      updatedAt: new Date('2026-10-26T11:00:00Z'),
    },
  };
  const peerQueries: unknown[] = [];
  const control = {
    edgePeer: {
      findUnique: (q: {
        where: { tenantId_agentId: { tenantId: string; agentId: string } };
      }) => {
        peerQueries.push(q);
        const { tenantId, agentId } = q.where.tenantId_agentId;
        return Promise.resolve(rows[`${tenantId}/${agentId}`] ?? null);
      },
    },
  } as unknown as ControlPrismaService;
  const tenants = {
    getClient: (tenantId: string) =>
      Promise.resolve({
        agent: {
          findUnique: ({ where }: { where: { id: string } }) =>
            Promise.resolve(
              agents[tenantId]?.includes(where.id) ? { id: where.id } : null,
            ),
        },
      }),
  } as unknown as TenantDatabaseManager;
  const peers = new EdgePeerService(
    control,
    tenants,
    config({ MANAR_EDGE_ENABLED: 'false' }),
    {} as ModuleRef,
    {} as AuditService,
  );
  const controller = new EgressRulesController(
    tenants,
    {} as AuditService,
    peers,
  );
  const auth = (tenantId: string) =>
    ({ tenant: { id: tenantId }, user: { id: 'u' } }) as AuthContext;

  it('returns the stored state and reason of a cut peer, no key, slugs or allow-list', async () => {
    const res = await controller.edge(auth('t1'), 'a1');
    expect(res).toEqual({
      enrolled: true,
      state: 'cut',
      cutReasons: ['agent_quarantined'],
      address: '100.88.0.2/32',
      updatedAt: '2026-10-26T10:00:00.000Z',
    });
  });

  it('an active peer has no cut reasons; an agent without a peer is not enrolled', async () => {
    expect(await controller.edge(auth('t2'), 'a2')).toEqual({
      enrolled: true,
      state: 'active',
      address: '100.88.0.3/32',
      updatedAt: '2026-10-26T11:00:00.000Z',
    });
    expect(await controller.edge(auth('t1'), 'a3')).toEqual({
      enrolled: false,
    });
  });

  it("404 for another tenant's agent, without reading the peer registry", async () => {
    peerQueries.length = 0;
    await expect(controller.edge(auth('t2'), 'a1')).rejects.toBeInstanceOf(
      NotFoundException,
    );
    await expect(controller.edge(auth('t1'), 'a2')).rejects.toBeInstanceOf(
      NotFoundException,
    );
    expect(peerQueries).toEqual([]);
  });

  it("an agent id that exists in two tenants never returns the other tenant's peer", async () => {
    expect(await controller.edge(auth('t2'), 'same')).toEqual({
      enrolled: false,
    });
    expect(await controller.edge(auth('t1'), 'same')).toMatchObject({
      enrolled: true,
      address: '100.88.0.4/32',
    });
  });

  it('reads the peer by the caller tenant and agent only', async () => {
    peerQueries.length = 0;
    await controller.edge(auth('t1'), 'a1');
    expect(peerQueries).toEqual([
      expect.objectContaining({
        where: { tenantId_agentId: { tenantId: 't1', agentId: 'a1' } },
      }),
    ]);
  });
});
