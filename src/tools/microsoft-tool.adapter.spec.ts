import type { AddressInfo } from 'node:net';
import type { ConfigService } from '@nestjs/config';
import type { FastifyInstance } from 'fastify';
import { Logger } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AppConfig } from '../config/env.validation';
import {
  buildMicrosoftFixtureApp,
  FIXTURE_DEFAULTS,
  type MicrosoftFixtureOptions,
} from '../../packages/demo-soc-tools/src/microsoft/fixture';
import {
  FIXTURE_INCIDENT_ID,
  FIXTURE_MACHINE_ID,
  FIXTURE_USER_ID,
} from '../../packages/demo-soc-tools/src/microsoft/seed-data';
import { findMicrosoftAction, MICROSOFT_ACTIONS } from './microsoft-actions';
import { MicrosoftToolAdapter } from './microsoft-tool.adapter';
import type { ToolActionRecord, ToolRecord } from './tool-registry.service';

/**
 * `MicrosoftToolAdapter` against the in-process DEMO FIXTURE
 * (`packages/demo-soc-tools/src/microsoft/fixture.ts`) over real loopback
 * HTTP. Proves the adapter's token handling, request shapes and outcome
 * mapping; says nothing about a live Microsoft tenant.
 */

function config(allowLoopback = true): ConfigService<AppConfig, true> {
  const values: Record<string, unknown> = {
    NODE_ENV: 'test',
    SSRF_ALLOWED_HOSTS: '127.0.0.1',
    SSRF_ALLOW_LOOPBACK: allowLoopback,
  };
  return { get: (key: string) => values[key] } as never;
}

function action(name: string): ToolActionRecord {
  const def = findMicrosoftAction(name);
  return {
    id: `row-${name}`,
    toolId: 'tool',
    name,
    description: null,
    riskBaseScore: def?.riskBaseScore ?? 0,
    inputSchema: null,
    outputSchema: null,
    mutating: def?.mutating ?? true,
    destructive: def?.destructive ?? true,
    approvalDefault: false,
    classification: 'INTERNAL',
  };
}

interface FixtureRequest {
  method: string;
  path: string;
  query: Record<string, string>;
  body: Record<string, unknown> | null;
}

describe('MicrosoftToolAdapter (against the DEMO FIXTURE)', () => {
  let fixture: FastifyInstance;
  let base: string;
  let adapter: MicrosoftToolAdapter;

  async function start(options: MicrosoftFixtureOptions = {}) {
    fixture = buildMicrosoftFixtureApp(options);
    await fixture.listen({ port: 0, host: '127.0.0.1' });
    base = `http://127.0.0.1:${(fixture.server.address() as AddressInfo).port}/microsoft`;
  }

  function tool(
    api: 'graph' | 'defender',
    metadata: Record<string, unknown> = {},
  ): ToolRecord {
    return {
      id: `tool-${api}`,
      name: `microsoft-${api}`,
      type: api === 'graph' ? 'IAM' : 'EDR',
      vendor: 'Microsoft',
      description: null,
      baseEndpoint:
        api === 'graph' ? `${base}/graph/v1.0` : `${base}/defender/api`,
      protocol: 'MICROSOFT',
      credentialReference: { provider: 'OPENBAO', reference: 'unused' },
      enabled: true,
      metadata: {
        api,
        azureTenantId: FIXTURE_DEFAULTS.tenantId,
        clientId: FIXTURE_DEFAULTS.clientId,
        authorityUrl: `${base}/login`,
        requestTimeoutMs: 1_000,
        ...metadata,
      },
    };
  }

  const graph = () => tool('graph');
  const defender = () => tool('defender');
  const secret = FIXTURE_DEFAULTS.clientSecret;

  function invoke(
    t: ToolRecord,
    name: string,
    resource: string,
    params: unknown = {},
    credential: string = secret,
  ) {
    return adapter.invoke(t, action(name), resource, params, credential);
  }

  async function fixtureGet<T>(path: string): Promise<T> {
    return (await fetch(`${base}/_fixture/${path}`)).json() as Promise<T>;
  }
  const requests = async () =>
    (await fixtureGet<{ requests: FixtureRequest[] }>('requests')).requests;
  const tokenRequests = async () =>
    (await fixtureGet<{ tokenRequests: number }>('state')).tokenRequests;

  async function fault(body: Record<string, unknown>) {
    await fetch(`${base}/_fixture/faults`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  beforeEach(async () => {
    await start();
    adapter = new MicrosoftToolAdapter(config());
  });

  afterEach(async () => {
    await fixture.close();
  });

  it('declares every action with a scope-bearing API, a permission and consistent flags', () => {
    for (const def of MICROSOFT_ACTIONS) {
      expect(def.permissions.length).toBeGreaterThan(0);
      if (def.destructive) expect(def.mutating).toBe(true);
    }
  });

  describe('token acquisition', () => {
    it('gets one token per API scope and reuses it until shortly before expiry', async () => {
      const first = await invoke(
        graph(),
        'security.incident.get',
        FIXTURE_INCIDENT_ID,
      );
      expect(first).toMatchObject({
        success: true,
        data: { id: FIXTURE_INCIDENT_ID, _dataOrigin: 'DEMO_FIXTURE' },
      });
      await invoke(graph(), 'security.alert.list', 'all');
      expect(await tokenRequests()).toBe(1);

      // Defender needs its own audience; the fixture rejects a Graph token there.
      const device = await invoke(
        defender(),
        'defender.machine.get',
        FIXTURE_MACHINE_ID,
      );
      expect(device.success).toBe(true);
      expect(await tokenRequests()).toBe(2);
    });

    it('fetches a new token when the cached one is within the expiry skew', async () => {
      await fixture.close();
      await start({ tokenTtlSeconds: 30 });
      await invoke(graph(), 'security.incident.list', 'all');
      await invoke(graph(), 'security.incident.list', 'all');
      expect(await tokenRequests()).toBe(2);
    });

    it('never serves a token cached for another client secret', async () => {
      expect(
        (await invoke(graph(), 'security.incident.list', 'all')).success,
      ).toBe(true);
      const wrong = await invoke(
        graph(),
        'security.incident.list',
        'all',
        {},
        'not-the-secret',
      );
      expect(wrong).toEqual({
        success: false,
        errorMessage: 'token_acquisition_failed',
      });
    });

    it('fails definitely, without sending the action, when the token endpoint errors', async () => {
      await fault({
        method: 'POST',
        path: `/login/${FIXTURE_DEFAULTS.tenantId}/oauth2/v2.0/token`,
        status: 503,
      });
      const result = await invoke(
        graph(),
        'entra.user.disable',
        FIXTURE_USER_ID,
      );
      expect(result).toEqual({
        success: false,
        errorMessage: 'token_acquisition_failed',
      });
      expect((await requests()).map((r) => r.method)).toEqual(['POST']);
      const state = await fixtureGet<{
        users: { id: string; accountEnabled: boolean }[];
      }>('state');
      expect(
        state.users.find((u) => u.id === FIXTURE_USER_ID)?.accountEnabled,
      ).toBe(true);
    });

    it('fails definitely when the token endpoint is unreachable', async () => {
      const t = tool('graph', { authorityUrl: 'http://127.0.0.1:1/login' });
      const result = await invoke(t, 'entra.user.disable', FIXTURE_USER_ID);
      expect(result).toEqual({
        success: false,
        errorMessage: 'token_acquisition_failed',
      });
      expect(result.outcomeUnknown).toBeUndefined();
    });

    it('refuses plain HTTP, sending neither secret nor token, outside development', async () => {
      adapter = new MicrosoftToolAdapter(config(false));
      const warn = vi.spyOn(Logger.prototype, 'warn');
      const result = await invoke(graph(), 'security.incident.list', 'all');
      expect(result).toEqual({
        success: false,
        errorMessage: 'token_acquisition_failed',
      });
      expect(await requests()).toEqual([]);
      expect(String(warn.mock.calls.at(-1)?.[0])).toContain('https_required');
      warn.mockRestore();
    });

    it('drops a token Microsoft rejected with 401 and gets a new one next time', async () => {
      await fault({
        method: 'GET',
        path: '/graph/v1.0/security/incidents',
        status: 401,
      });
      const rejected = await invoke(graph(), 'security.incident.list', 'all');
      expect(rejected).toEqual({
        success: false,
        errorMessage: 'HTTP 401 FixtureInjectedFault',
      });
      expect(
        (await invoke(graph(), 'security.incident.list', 'all')).success,
      ).toBe(true);
      expect(await tokenRequests()).toBe(2);
    });
  });

  describe('request shapes', () => {
    const lastCall = async () => (await requests()).at(-1)!;

    it.each([
      [
        'entra.user.disable',
        FIXTURE_USER_ID,
        {},
        'PATCH',
        `/graph/v1.0/users/${FIXTURE_USER_ID}`,
        { accountEnabled: false },
      ],
      [
        'entra.user.enable',
        FIXTURE_USER_ID,
        {},
        'PATCH',
        `/graph/v1.0/users/${FIXTURE_USER_ID}`,
        { accountEnabled: true },
      ],
      [
        'entra.user.sessions.revoke',
        FIXTURE_USER_ID,
        {},
        'POST',
        `/graph/v1.0/users/${FIXTURE_USER_ID}/revokeSignInSessions`,
        null,
      ],
      [
        'entra.user.risk.confirmCompromised',
        FIXTURE_USER_ID,
        {},
        'POST',
        '/graph/v1.0/identityProtection/riskyUsers/confirmCompromised',
        { userIds: [FIXTURE_USER_ID] },
      ],
      [
        'entra.user.risk.dismiss',
        FIXTURE_USER_ID,
        {},
        'POST',
        '/graph/v1.0/identityProtection/riskyUsers/dismiss',
        { userIds: [FIXTURE_USER_ID] },
      ],
    ] as const)('%s', async (name, resource, params, method, path, body) => {
      const result = await invoke(graph(), name, resource, params);
      expect(result.success).toBe(true);
      expect(await lastCall()).toMatchObject({ method, path, body });
    });

    it.each([
      [
        'defender.machine.isolate',
        { comment: 'c' },
        'isolate',
        { Comment: 'c', IsolationType: 'Full' },
      ],
      [
        'defender.machine.isolate',
        { comment: 'c', isolationType: 'Selective' },
        'isolate',
        { Comment: 'c', IsolationType: 'Selective' },
      ],
      [
        'defender.machine.unisolate',
        { comment: 'c' },
        'unisolate',
        { Comment: 'c' },
      ],
      [
        'defender.machine.antivirusScan',
        { comment: 'c' },
        'runAntiVirusScan',
        { Comment: 'c', ScanType: 'Quick' },
      ],
      [
        'defender.machine.collectInvestigationPackage',
        { comment: 'c' },
        'collectInvestigationPackage',
        { Comment: 'c' },
      ],
      [
        'defender.machine.stopAndQuarantineFile',
        { comment: 'c', sha1: '3395856ce81f2b7382dee72602f798b642f14140' },
        'StopAndQuarantineFile',
        { Comment: 'c', Sha1: '3395856ce81f2b7382dee72602f798b642f14140' },
      ],
    ] as const)('%s %j', async (name, params, endpoint, body) => {
      const result = await invoke(defender(), name, FIXTURE_MACHINE_ID, params);
      expect(result).toMatchObject({
        success: true,
        data: { machineId: FIXTURE_MACHINE_ID },
      });
      expect(await lastCall()).toMatchObject({
        method: 'POST',
        path: `/defender/api/machines/${FIXTURE_MACHINE_ID}/${endpoint}`,
        body,
      });
    });

    it('resets the password to a random value that is never returned', async () => {
      const result = await invoke(
        graph(),
        'entra.user.password.reset',
        FIXTURE_USER_ID,
      );
      const call = await lastCall();
      const profile = call.body?.passwordProfile as {
        password: string;
        forceChangePasswordNextSignIn: boolean;
      };
      expect(call).toMatchObject({
        method: 'PATCH',
        path: `/graph/v1.0/users/${FIXTURE_USER_ID}`,
      });
      expect(profile.forceChangePasswordNextSignIn).toBe(true);
      expect(profile.password.length).toBeGreaterThanOrEqual(32);
      expect(result.success).toBe(true);
      expect(JSON.stringify(result)).not.toContain(profile.password);

      await invoke(graph(), 'entra.user.password.reset', FIXTURE_USER_ID);
      const again = (await lastCall()).body?.passwordProfile as {
        password: string;
      };
      expect(again.password).not.toBe(profile.password);
    });

    it('filters sign-ins and machine actions by the authorized resource', async () => {
      await invoke(graph(), 'entra.user.signins.list', FIXTURE_USER_ID, {
        top: 5,
      });
      expect(await lastCall()).toMatchObject({
        path: '/graph/v1.0/auditLogs/signIns',
        query: { $filter: `userId eq '${FIXTURE_USER_ID}'`, $top: '5' },
      });
      await invoke(
        defender(),
        'defender.machineaction.list',
        FIXTURE_MACHINE_ID,
      );
      expect(await lastCall()).toMatchObject({
        path: '/defender/api/machineactions',
        query: { $filter: `machineId eq '${FIXTURE_MACHINE_ID}'` },
      });
    });

    it('rejects a resource or params outside the catalog before sending anything', async () => {
      const results = await Promise.all([
        invoke(graph(), 'entra.user.disable', '../security/incidents'),
        invoke(graph(), 'entra.user.signins.list', "x' or userId ne '"),
        invoke(graph(), 'entra.user.disable', FIXTURE_USER_ID, {
          userId: 'someone-else',
        }),
        invoke(defender(), 'defender.machine.isolate', FIXTURE_MACHINE_ID, {}),
        invoke(graph(), 'defender.machine.isolate', FIXTURE_MACHINE_ID, {
          comment: 'c',
        }),
        invoke(graph(), 'not.in.catalog', 'x'),
      ]);
      for (const r of results) expect(r.success).toBe(false);
      expect(results.at(-2)?.errorMessage).toBe('unknown_microsoft_action');
      expect(await requests()).toEqual([]);
    });
  });

  describe('outcome mapping', () => {
    const disablePath = `/graph/v1.0/users/${FIXTURE_USER_ID}`;

    it("maps a 4xx to a definite FAILURE carrying Microsoft's error code", async () => {
      const result = await invoke(
        graph(),
        'entra.user.disable',
        'nobody@fixture.example',
      );
      expect(result).toEqual({
        success: false,
        errorMessage: 'HTTP 404 Request_ResourceNotFound',
      });
    });

    it('does not retry a throttled (429) mutation and records it as a definite FAILURE', async () => {
      await fault({
        method: 'PATCH',
        path: disablePath,
        status: 429,
        times: 5,
      });
      const result = await invoke(
        graph(),
        'entra.user.disable',
        FIXTURE_USER_ID,
      );
      expect(result).toEqual({
        success: false,
        errorMessage: 'HTTP 429 FixtureInjectedFault',
      });
      expect(
        (await requests()).filter((r) => r.method === 'PATCH'),
      ).toHaveLength(1);
    });

    it('sends a mutation once and marks a 5xx outcomeUnknown', async () => {
      await fault({
        method: 'PATCH',
        path: disablePath,
        status: 503,
        times: 5,
      });
      const result = await invoke(
        graph(),
        'entra.user.disable',
        FIXTURE_USER_ID,
      );
      expect(result).toEqual({
        success: false,
        errorMessage: 'HTTP 503 FixtureInjectedFault',
        outcomeUnknown: true,
      });
      expect(
        (await requests()).filter((r) => r.method === 'PATCH'),
      ).toHaveLength(1);
    });

    it('marks a mutation that timed out outcomeUnknown', async () => {
      const path = `/defender/api/machines/${FIXTURE_MACHINE_ID}/isolate`;
      await fault({ method: 'POST', path, delayMs: 1_500 });
      const result = await invoke(
        defender(),
        'defender.machine.isolate',
        FIXTURE_MACHINE_ID,
        { comment: 'c' },
      );
      expect(result).toEqual({
        success: false,
        errorMessage: 'request timed out',
        outcomeUnknown: true,
      });
    });

    it('marks a mutation whose connection dropped after sending outcomeUnknown', async () => {
      await fault({ method: 'PATCH', path: disablePath, drop: true });
      const result = await invoke(
        graph(),
        'entra.user.disable',
        FIXTURE_USER_ID,
      );
      expect(result).toEqual({
        success: false,
        errorMessage: 'request failed',
        outcomeUnknown: true,
      });
    });

    it('retries a read after a transient 5xx', async () => {
      await fault({
        method: 'GET',
        path: '/graph/v1.0/security/incidents',
        status: 503,
      });
      const result = await invoke(graph(), 'security.incident.list', 'all');
      expect(result.success).toBe(true);
      expect((await requests()).filter((r) => r.method === 'GET')).toHaveLength(
        2,
      );
    });
  });
});
