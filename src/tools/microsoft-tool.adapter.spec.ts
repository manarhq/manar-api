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
  FIXTURE_DYNAMIC_GROUP_ID,
  FIXTURE_GROUP_ID,
  FIXTURE_INCIDENT_ID,
  FIXTURE_MACHINE_ID,
  FIXTURE_SECOND_USER_ID,
  FIXTURE_USER_ID,
  FIXTURE_USER_UPN,
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
      expect(['build', 'run'].filter((k) => k in def)).toHaveLength(1);
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

    it('resets the password to a temporary value handed over for the approver only, never in data', async () => {
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
      expect(profile.password.length).toBeGreaterThanOrEqual(24);
      expect(result.success).toBe(true);
      expect(result.handover).toEqual({ temporaryPassword: profile.password });
      expect(JSON.stringify(result.data)).not.toContain(profile.password);

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

  describe('helpdesk and joiner/leaver actions', () => {
    interface State {
      users: {
        id: string;
        userPrincipalName: string;
        accountEnabled: boolean;
        sessionsRevokedAt: string | null;
        authMethods: { '@odata.type': string }[];
      }[];
      groups: { id: string; members: string[] }[];
    }
    const state = () => fixtureGet<State>('state');
    const user = async (id: string) =>
      (await state()).users.find((u) => u.id === id)!;
    const members = async (groupId: string) =>
      (await state()).groups.find((g) => g.id === groupId)!.members;
    const mutations = async () =>
      (await requests()).filter(
        (r) => r.method !== 'GET' && !r.path.startsWith('/login/'),
      );
    const lastCall = async () => (await requests()).at(-1)!;

    it('mfa.reset removes every method but the password, phone last, then revokes sessions', async () => {
      const result = await invoke(
        graph(),
        'entra.user.mfa.reset',
        FIXTURE_USER_ID,
      );
      expect(result).toMatchObject({
        success: true,
        data: {
          methodsRemoved: ['microsoftAuthenticatorMethods', 'phoneMethods'],
          methodsKept: ['passwordAuthenticationMethod'],
          sessionsRevoked: true,
        },
      });
      expect((await mutations()).map((r) => `${r.method} ${r.path}`)).toEqual([
        expect.stringMatching(/^DELETE .*\/microsoftAuthenticatorMethods\//),
        expect.stringMatching(/^DELETE .*\/phoneMethods\//),
        `POST /graph/v1.0/users/${FIXTURE_USER_ID}/revokeSignInSessions`,
      ]);
      const after = await user(FIXTURE_USER_ID);
      expect(after.authMethods.map((m) => m['@odata.type'])).toEqual([
        '#microsoft.graph.passwordAuthenticationMethod',
      ]);
      expect(after.sessionsRevokedAt).not.toBeNull();
    });

    it('mfa.reset that fails after removing a method is a partial, UNKNOWN outcome', async () => {
      await fault({
        method: 'DELETE',
        path: `/graph/v1.0/users/${FIXTURE_USER_ID}/authentication/phoneMethods/3179e48a-750b-4051-897c-87b9720928f7`,
        status: 403,
      });
      const result = await invoke(
        graph(),
        'entra.user.mfa.reset',
        FIXTURE_USER_ID,
      );
      expect(result).toEqual({
        success: false,
        outcomeUnknown: true,
        errorMessage:
          'partial: done microsoftAuthenticatorMethods; phoneMethods failed (HTTP 403 FixtureInjectedFault)',
      });
    });

    it('mfa.reset that cannot list methods fails definitely, with nothing changed', async () => {
      const result = await invoke(
        graph(),
        'entra.user.mfa.reset',
        'nobody@fixture.example',
      );
      expect(result).toEqual({
        success: false,
        errorMessage: 'HTTP 404 Request_ResourceNotFound',
      });
      expect(await mutations()).toEqual([]);
    });

    it('unlock re-enables the account', async () => {
      await invoke(graph(), 'entra.user.disable', FIXTURE_USER_ID);
      const result = await invoke(
        graph(),
        'entra.user.unlock',
        FIXTURE_USER_ID,
      );
      expect(result.success).toBe(true);
      expect((await user(FIXTURE_USER_ID)).accountEnabled).toBe(true);
    });

    it('lists, adds and removes group members, resolving a UPN to its object id', async () => {
      const listed = await invoke(
        graph(),
        'entra.group.members.list',
        FIXTURE_GROUP_ID,
      );
      expect(listed).toMatchObject({
        success: true,
        data: { value: [{ id: FIXTURE_USER_ID }] },
      });

      const membership = `${FIXTURE_GROUP_ID}:lee.gu@fixture.example`;
      const added = await invoke(graph(), 'entra.group.member.add', membership);
      expect(added).toMatchObject({
        success: true,
        data: {
          added: true,
          groupId: FIXTURE_GROUP_ID,
          userId: FIXTURE_SECOND_USER_ID,
        },
      });
      expect(await lastCall()).toMatchObject({
        method: 'POST',
        path: `/graph/v1.0/groups/${FIXTURE_GROUP_ID}/members/$ref`,
        body: {
          '@odata.id': `https://graph.microsoft.com/v1.0/directoryObjects/${FIXTURE_SECOND_USER_ID}`,
        },
      });
      expect(await members(FIXTURE_GROUP_ID)).toContain(FIXTURE_SECOND_USER_ID);

      // Graph refuses a second add; nothing changed, so a definite FAILURE.
      expect(
        await invoke(graph(), 'entra.group.member.add', membership),
      ).toEqual({
        success: false,
        errorMessage: 'HTTP 400 Request_BadRequest',
      });

      const removed = await invoke(
        graph(),
        'entra.group.member.remove',
        `${FIXTURE_GROUP_ID}:${FIXTURE_SECOND_USER_ID}`,
      );
      expect(removed).toMatchObject({ success: true, data: { removed: true } });
      expect(await members(FIXTURE_GROUP_ID)).not.toContain(
        FIXTURE_SECOND_USER_ID,
      );
    });

    it('rejects a membership resource without both a group id and a user', async () => {
      const results = await Promise.all(
        [
          FIXTURE_GROUP_ID,
          `not-a-guid:${FIXTURE_USER_ID}`,
          `${FIXTURE_GROUP_ID}:../x`,
        ].map((r) => invoke(graph(), 'entra.group.member.add', r)),
      );
      for (const r of results) expect(r.success).toBe(false);
      expect(await requests()).toEqual([]);
    });

    it('create makes a disabled user with a temporary password for the approver only', async () => {
      const upn = 'new.joiner@fixture.example';
      const result = await invoke(graph(), 'entra.user.create', upn, {
        displayName: 'New Joiner',
        department: 'IT',
      });
      const call = await lastCall();
      expect(call).toMatchObject({
        method: 'POST',
        path: '/graph/v1.0/users',
        body: {
          userPrincipalName: upn,
          mailNickname: 'new.joiner',
          displayName: 'New Joiner',
          accountEnabled: false,
          department: 'IT',
          passwordProfile: { forceChangePasswordNextSignIn: true },
        },
      });
      const password = (call.body?.passwordProfile as { password: string })
        .password;
      expect(result).toMatchObject({
        success: true,
        data: { userPrincipalName: upn, accountEnabled: false },
        handover: { temporaryPassword: password },
      });
      expect(JSON.stringify(result.data)).not.toContain(password);
      expect(
        (await state()).users.find((u) => u.userPrincipalName === upn),
      ).toBeDefined();
    });

    it('create needs a UPN resource and a display name', async () => {
      const results = await Promise.all([
        invoke(graph(), 'entra.user.create', 'no-domain', { displayName: 'x' }),
        invoke(graph(), 'entra.user.create', 'a@fixture.example', {}),
        invoke(graph(), 'entra.user.create', 'a@fixture.example', {
          displayName: 'x',
          passwordProfile: { password: 'chosen-by-the-agent' },
        }),
      ]);
      for (const r of results) expect(r.success).toBe(false);
      expect(await requests()).toEqual([]);
    });

    it('offboard disables, revokes sessions, leaves static groups, keeps dynamic ones and declares the handover', async () => {
      const result = await invoke(
        graph(),
        'entra.user.offboard',
        FIXTURE_USER_UPN,
      );
      expect(result).toMatchObject({
        success: true,
        data: {
          userId: FIXTURE_USER_ID,
          disabled: true,
          sessionsRevoked: true,
          groupsRemoved: [FIXTURE_GROUP_ID],
          groupsKeptDynamic: [FIXTURE_DYNAMIC_GROUP_ID],
          handover: {
            mailbox: expect.stringMatching(/^declared-only/) as unknown,
            oneDrive: expect.stringMatching(/^declared-only/) as unknown,
          },
        },
      });
      const after = await user(FIXTURE_USER_ID);
      expect(after.accountEnabled).toBe(false);
      expect(after.sessionsRevokedAt).not.toBeNull();
      expect(await members(FIXTURE_GROUP_ID)).not.toContain(FIXTURE_USER_ID);
      expect(await members(FIXTURE_DYNAMIC_GROUP_ID)).toContain(
        FIXTURE_USER_ID,
      );
    });

    it('offboard that fails after disabling is a partial, UNKNOWN outcome and goes no further', async () => {
      await fault({
        method: 'POST',
        path: `/graph/v1.0/users/${FIXTURE_USER_ID}/revokeSignInSessions`,
        status: 503,
      });
      const result = await invoke(
        graph(),
        'entra.user.offboard',
        FIXTURE_USER_ID,
      );
      expect(result).toEqual({
        success: false,
        outcomeUnknown: true,
        errorMessage:
          'partial: done disable; sessions.revoke failed (HTTP 503 FixtureInjectedFault)',
      });
      expect(await members(FIXTURE_GROUP_ID)).toContain(FIXTURE_USER_ID);
      expect(
        (await mutations()).filter((r) =>
          r.path.endsWith('revokeSignInSessions'),
        ),
      ).toHaveLength(1);
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
