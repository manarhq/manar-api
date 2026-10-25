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
import type { ControlPrismaService } from '../database/control-prisma.service';
import type { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { EdgeGatewayGuard } from './edge-internal.controller';
import type { EdgePeerService } from './edge-peer.service';
import {
  gatewayIp,
  isWgPublicKey,
  nextFreeAddress,
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

function guardContext(authorization?: string): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => ({ headers: { authorization } }),
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
  function controller(enabled: boolean) {
    const touched: string[] = [];
    const c = new AgentEnrollController(
      {
        enroll: () => {
          touched.push('enroll');
          return Promise.reject(new Error('not reached'));
        },
      } as unknown as AgentsService,
      {
        tenant: {
          findUnique: () => {
            touched.push('tenant');
            return Promise.resolve(null);
          },
        },
      } as unknown as ControlPrismaService,
      {} as TenantDatabaseManager,
      { enabled } as EdgePeerService,
    );
    return { c, touched };
  }

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
});
