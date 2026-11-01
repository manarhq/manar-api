import { NotFoundException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { HostAuthGuard } from '../host-mtls/host-auth.guard';
import type { HostContext } from '../host-mtls/host-context';
import { HostAuthorizeService } from './host-authorize.service';
import { HostCoverageController } from './host-coverage.controller';
import {
  HostToolsService,
  effectiveProtection,
  enforcementLabel,
} from './host-tools.service';

const hostA: HostContext = {
  hostId: 'h-a',
  tenantId: 't-a',
  machineId: 'm',
  ownerSubject: null,
  status: 'APPROVED',
};

function toolsDb() {
  const rows = new Map<string, Record<string, unknown>>();
  const key = (w: { hostId: string; toolId: string }) =>
    `${w.hostId}|${w.toolId}`;
  return {
    rows,
    client: {
      tool: { upsert: vi.fn(() => Promise.resolve({ id: 'x' })) },
      toolAction: { upsert: vi.fn(() => Promise.resolve({})) },
      host: {
        update: vi.fn(() => Promise.resolve({})),
        findMany: vi.fn(() => Promise.resolve([])),
      },
      hostTool: {
        findMany: vi.fn(() => Promise.resolve([...rows.values()])),
        findUnique: vi.fn(
          ({
            where,
          }: {
            where: { hostId_toolId: { hostId: string; toolId: string } };
          }) => Promise.resolve(rows.get(key(where.hostId_toolId)) ?? null),
        ),
        upsert: vi.fn(
          ({
            where,
            create,
            update,
          }: {
            where: { hostId_toolId: { hostId: string; toolId: string } };
            create: Record<string, unknown>;
            update: Record<string, unknown>;
          }) => {
            const k = key(where.hostId_toolId);
            rows.set(
              k,
              rows.has(k)
                ? { ...rows.get(k), ...update }
                : { id: k, desiredProtection: true, ...create },
            );
            return Promise.resolve({});
          },
        ),
        updateMany: vi.fn(
          ({
            where,
            data,
          }: {
            where: { toolId: { notIn: string[] } };
            data: Record<string, unknown>;
          }) => {
            for (const [k, v] of rows)
              if (!where.toolId.notIn.includes(v.toolId as string))
                rows.set(k, { ...v, ...data });
            return Promise.resolve({});
          },
        ),
        update: vi.fn(
          ({
            where,
            data,
          }: {
            where: { id: string };
            data: Record<string, unknown>;
          }) => {
            rows.set(where.id, { ...rows.get(where.id), ...data });
            return Promise.resolve({});
          },
        ),
      },
    },
  };
}

function toolsService() {
  const a = toolsDb();
  const b = toolsDb();
  const audit = { recordSafely: vi.fn(() => Promise.resolve({ id: 'e' })) };
  const tenants = {
    getClient: vi.fn((id: string) =>
      Promise.resolve(id === 't-a' ? a.client : b.client),
    ),
  };
  return {
    svc: new HostToolsService(tenants as never, audit as never),
    a,
    b,
    audit,
    tenants,
  };
}

describe('enforcement label', () => {
  it('is governed only for a hook the catalogue allows, and never for an observe-only tool', () => {
    expect(
      enforcementLabel(
        'host.cursor',
        { protected: true, protectMode: 'hook' },
        true,
      ),
    ).toBe('governed');
    expect(
      enforcementLabel(
        'host.cursor',
        { protected: true, protectMode: 'mcp' },
        true,
      ),
    ).toBe('observed-only');
    expect(
      enforcementLabel(
        'host.cursor',
        { protected: false, protectMode: 'none' },
        true,
      ),
    ).toBe('observed-only');
    // Even a row that somehow says hook:
    expect(
      enforcementLabel(
        'host.chatgpt-desktop',
        { protected: true, protectMode: 'hook' },
        true,
      ),
    ).toBe('observed-only');
    expect(
      enforcementLabel(
        'host.vscode-copilot',
        { protected: true, protectMode: 'hook' },
        true,
      ),
    ).toBe('observed-only');
    expect(
      enforcementLabel(
        'other:foo',
        { protected: true, protectMode: 'hook' },
        true,
      ),
    ).toBe('observed-only');
    expect(
      enforcementLabel(
        'host.cursor',
        { protected: true, protectMode: 'hook' },
        false,
      ),
    ).toBe('monitoring unavailable');
  });
  it('caps what a device claims to what the catalogue allows', () => {
    expect(effectiveProtection('host.chatgpt-desktop', true, 'hook')).toEqual({
      protected: false,
      protectMode: 'none',
    });
    expect(effectiveProtection('host.claude-desktop', true, 'hook')).toEqual({
      protected: false,
      protectMode: 'none',
    });
    expect(effectiveProtection('host.claude-desktop', true, 'mcp')).toEqual({
      protected: true,
      protectMode: 'mcp',
    });
  });
});

describe('HostToolsService', () => {
  const inv = (tools: unknown[]) => ({ tools }) as never;
  it('stores the inventory, audits discovery and protection once, and drops tools that are gone', async () => {
    const { svc, a, audit } = toolsService();
    const cursor = {
      id: 'host.cursor',
      name: 'Cursor',
      version: '2.1',
      path: '/usr/bin/cursor',
      protected: true,
      protectMode: 'hook',
    };
    await svc.report(
      hostA,
      inv([
        cursor,
        {
          id: 'host.chatgpt-desktop',
          name: 'ChatGPT',
          protected: true,
          protectMode: 'hook',
        },
      ]),
    );
    expect(a.rows.get('h-a|host.chatgpt-desktop')).toMatchObject({
      protected: false,
      protectMode: 'none',
    });
    const types = () =>
      audit.recordSafely.mock.calls.map(
        (c) =>
          (c as unknown as [unknown, unknown, { eventType: string }])[2]
            .eventType,
      );
    expect(types().sort()).toEqual([
      'tool.discovered',
      'tool.discovered',
      'tool.protected',
    ]);
    await svc.report(hostA, inv([cursor]));
    expect(types()).toHaveLength(3); // unchanged report: no new events
    expect(a.rows.get('h-a|host.chatgpt-desktop')).toMatchObject({
      missing: true,
      protected: false,
    });
    await svc.report(
      hostA,
      inv([{ ...cursor, protected: false, protectMode: 'none' }]),
    );
    expect(types().at(-1)).toBe('tool.unprotected');
  });
  it("keeps the owner's choice when a scan misses the tool, and shows it again when it returns", async () => {
    const { svc, a } = toolsService();
    const t = {
      id: 'host.cursor',
      name: 'Cursor',
      protected: true,
      protectMode: 'hook',
    };
    await svc.report(hostA, inv([t]));
    await svc.setDesired('t-a', 'h-a', 'host.cursor', false, {
      type: 'human',
      id: 'u',
    });
    await svc.report(hostA, inv([])); // one scan that missed it
    expect(a.rows.get('h-a|host.cursor')).toMatchObject({
      missing: true,
      desiredProtection: false,
    });
    expect(await svc.instructions(hostA)).toEqual({
      unprotect: ['host.cursor'],
    });
    await svc.report(
      hostA,
      inv([{ ...t, protected: false, protectMode: 'none' }]),
    );
    expect(a.rows.get('h-a|host.cursor')).toMatchObject({
      missing: false,
      desiredProtection: false,
    });
  });
  it('rejects unknown catalogue ids and duplicates', async () => {
    const { svc } = toolsService();
    await expect(
      svc.report(
        hostA,
        inv([
          { id: 'host.nope', name: 'x', protected: false, protectMode: 'none' },
        ]),
      ),
    ).rejects.toThrow();
    const t = {
      id: 'host.cursor',
      name: 'x',
      protected: false,
      protectMode: 'none',
    };
    await expect(svc.report(hostA, inv([t, t]))).rejects.toThrow();
  });
  it('unprotect is delivered through the config instructions, and only for the same workspace', async () => {
    const { svc, tenants, a } = toolsService();
    await svc.report(
      hostA,
      inv([
        {
          id: 'host.cursor',
          name: 'Cursor',
          protected: true,
          protectMode: 'hook',
        },
      ]),
    );
    await svc.setDesired('t-a', 'h-a', 'host.cursor', false, {
      type: 'human',
      id: 'u',
    });
    expect(a.rows.get('h-a|host.cursor')).toMatchObject({
      desiredProtection: false,
    });
    expect(await svc.instructions(hostA)).toEqual({
      unprotect: ['host.cursor'],
    });
    // Tenant B's console cannot reach tenant A's device: its client has no such row.
    await expect(
      svc.setDesired('t-b', 'h-a', 'host.cursor', false, {
        type: 'human',
        id: 'u',
      }),
    ).rejects.toBeInstanceOf(NotFoundException);
    expect(tenants.getClient).toHaveBeenCalledWith('t-b');
  });
  it('refuses to switch protection on for a tool that can only be seen', async () => {
    const { svc } = toolsService();
    await svc.report(
      hostA,
      inv([
        {
          id: 'host.chatgpt-desktop',
          name: 'ChatGPT',
          protected: false,
          protectMode: 'none',
        },
      ]),
    );
    await expect(
      svc.setDesired('t-a', 'h-a', 'host.chatgpt-desktop', true, {
        type: 'human',
        id: 'u',
      }),
    ).rejects.toThrow();
  });
});

describe('HostAuthorizeService', () => {
  function make(
    over: {
      kill?: unknown;
      policy?: unknown;
      auditOk?: boolean;
      getClient?: unknown;
    } = {},
  ) {
    const tenants = {
      getClient:
        over.getClient ??
        vi.fn(() =>
          Promise.resolve({
            approvalAllowGrant: {
              findFirst: () => Promise.resolve(null),
              update: () => Promise.resolve({}),
            },
          }),
        ),
    };
    const kill = {
      checkAll: vi.fn(() => Promise.resolve(over.kill ?? { killed: false })),
    };
    const policy = {
      evaluate: vi.fn(() =>
        Promise.resolve(over.policy ?? { effect: 'ALLOW' }),
      ),
    };
    const audit = {
      recordSafely: vi.fn(() =>
        Promise.resolve(over.auditOk === false ? undefined : { id: 'e' }),
      ),
    };
    return {
      svc: new HostAuthorizeService(
        tenants as never,
        kill as never,
        policy as never,
        audit as never,
      ),
      tenants,
      kill,
      policy,
      audit,
    };
  }
  const req = (actionId: string, resource = 'x', toolId = 'host.cursor') => ({
    toolId,
    actionId,
    resource,
  });

  it('allows a read, asks for a shell command or an edit with no matching rule, and audits each', async () => {
    const { svc, audit } = make();
    expect((await svc.authorize(hostA, req('read'))).decision).toBe('ALLOW');
    expect(
      (await svc.authorize(hostA, req('shell', 'rm -rf x'))).decision,
    ).toBe('APPROVAL_REQUIRED');
    expect((await svc.authorize(hostA, req('edit', '/a'))).decision).toBe(
      'APPROVAL_REQUIRED',
    );
    expect(audit.recordSafely).toHaveBeenCalledTimes(3);
  });
  it('records the tool session id from the caller suffix, apart from the caller', async () => {
    const { svc, audit } = make();
    await svc.authorize(hostA, { ...req('read'), caller: 'uid:1000|s:abc-1' });
    await svc.authorize(hostA, { ...req('read'), caller: 'uid:1000|s:bad id' });
    const data = (i: number) =>
      (
        audit.recordSafely.mock.calls[i] as unknown as [
          unknown,
          unknown,
          { data: object },
        ]
      )[2].data;
    expect(data(0)).toMatchObject({ caller: 'uid:1000', sessionId: 'abc-1' });
    expect(data(1)).toMatchObject({
      caller: 'uid:1000|s:bad id',
      sessionId: null,
    });
  });
  it('obeys a matched rule over the risk fallback (a watch preset allows everything)', async () => {
    const { svc } = make({ policy: { effect: 'ALLOW', matchedRule: {} } });
    expect((await svc.authorize(hostA, req('shell'))).decision).toBe('ALLOW');
  });
  it('denies: policy deny, kill switch, pending host, unknown tool or action, policy failure', async () => {
    expect(
      (
        await make({
          policy: { effect: 'DENY', matchedRule: {} },
        }).svc.authorize(hostA, req('read'))
      ).reason,
    ).toBe('policy_denied');
    expect(
      (
        await make({
          kill: { killed: true, reason: 'tool_killed' },
        }).svc.authorize(hostA, req('read'))
      ).decision,
    ).toBe('DENY');
    expect(
      (await make().svc.authorize({ ...hostA, status: 'PENDING' }, req('read')))
        .reason,
    ).toBe('host_not_approved');
    expect(
      (await make().svc.authorize(hostA, req('read', 'x', 'host.evil'))).reason,
    ).toBe('unknown_tool');
    expect((await make().svc.authorize(hostA, req('teleport'))).reason).toBe(
      'unknown_action',
    );
    expect(
      (
        await make({
          policy: { effect: 'DENY', failureReason: 'policy_load_failed' },
        }).svc.authorize(hostA, req('read'))
      ).reason,
    ).toBe('policy_evaluation_failed');
  });
  it('fails closed when the tenant database or the audit write fails', async () => {
    const down = make({
      getClient: vi.fn(() => Promise.reject(new Error('db'))),
    });
    expect(await down.svc.authorize(hostA, req('read'))).toEqual({
      decision: 'DENY',
      reason: 'enforcement_dependency_unavailable',
    });
    expect(
      (await make({ auditOk: false }).svc.authorize(hostA, req('read')))
        .decision,
    ).toBe('DENY');
  });
  it('uses only the tenant of the verified certificate, whatever the body says', async () => {
    const { svc, tenants } = make();
    await svc.authorize({ ...hostA, tenantId: 't-b' }, {
      ...req('read'),
      tenantId: 't-a',
    } as never);
    expect(tenants.getClient).toHaveBeenCalledWith('t-b');
  });
});

describe('routes', () => {
  it('both device routes sit behind HostAuthGuard, which resolves the tenant from the certificate only', () => {
    expect(Reflect.getMetadata('__guards__', HostCoverageController)).toContain(
      HostAuthGuard,
    );
  });
});
