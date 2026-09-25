import { randomBytes, randomUUID } from 'node:crypto';
import Fastify, {
  type FastifyInstance,
  type FastifyReply,
  type FastifyRequest,
} from 'fastify';
import {
  seedData,
  type FixtureMachineAction,
  type FixtureSeed,
} from './seed-data';

/**
 * DEMO FIXTURE: a local, in-memory mimic of the three Microsoft endpoints
 * manar-api's Microsoft connector (`src/tools/microsoft-tool.adapter.ts`)
 * talks to — the Entra ID token endpoint, Microsoft Graph v1.0 and the
 * Defender for Endpoint API. It exists so the connector can be exercised
 * end to end before a customer tenant is available. It is not Microsoft,
 * proves nothing about behaviour against a live tenant, and every JSON
 * object it returns carries `"_dataOrigin": "DEMO_FIXTURE"`.
 *
 * Layout under the mount prefix (`/microsoft` in `app.ts`):
 *   POST /login/:tenant/oauth2/v2.0/token      client-credentials grant
 *   /graph/v1.0/...                             Graph routes (graph token)
 *   /defender/api/...                           Defender routes (defender token)
 *   /_fixture/{reset,state,requests,faults}     test/demo controls, no auth
 */

export const FIXTURE_DEFAULTS = {
  tenantId: '00000000-0000-4000-8000-00000000f1c5',
  clientId: '11111111-2222-4333-8444-555555555555',
  /** Dev-only fixture secret; the connector reads it from OpenBao like a real one. */
  clientSecret: 'manar-dev-microsoft-fixture-secret',
  tokenTtlSeconds: 3599,
} as const;

export const GRAPH_SCOPE = 'https://graph.microsoft.com/.default';
export const DEFENDER_SCOPE =
  'https://api.securitycenter.microsoft.com/.default';

export interface MicrosoftFixtureOptions {
  tenantId?: string;
  clientId?: string;
  clientSecret?: string;
  tokenTtlSeconds?: number;
}

type Audience = 'graph' | 'defender';

interface Fault {
  status?: number;
  delayMs?: number;
  /** Destroy the connection after the request was received, without answering. */
  drop?: boolean;
  remaining: number;
}

interface RecordedRequest {
  method: string;
  path: string;
  query: Record<string, unknown>;
  body: unknown;
}

class FixtureState {
  users = new Map<string, FixtureSeed['users'][number]>();
  riskyUsers = new Map<string, FixtureSeed['riskyUsers'][number]>();
  machines = new Map<string, FixtureSeed['machines'][number]>();
  incidents: FixtureSeed['incidents'] = [];
  alerts: FixtureSeed['alerts'] = [];
  signIns: FixtureSeed['signIns'] = [];
  machineActions: FixtureMachineAction[] = [];
  isolated = new Set<string>();
  tokens = new Map<string, { audience: Audience; expiresAt: number }>();
  tokenRequests = 0;
  requests: RecordedRequest[] = [];
  faults = new Map<string, Fault>();

  constructor() {
    this.reset();
  }

  reset(): void {
    const seed = seedData();
    this.users = new Map(seed.users.map((u) => [u.id, u]));
    this.riskyUsers = new Map(seed.riskyUsers.map((u) => [u.id, u]));
    this.machines = new Map(seed.machines.map((m) => [m.id, m]));
    this.incidents = seed.incidents;
    this.alerts = seed.alerts;
    this.signIns = seed.signIns;
    this.machineActions = [];
    this.isolated.clear();
    this.tokens.clear();
    this.tokenRequests = 0;
    this.requests = [];
    this.faults.clear();
  }

  findUser(idOrUpn: string) {
    return (
      this.users.get(idOrUpn) ??
      [...this.users.values()].find(
        (u) => u.userPrincipalName.toLowerCase() === idOrUpn.toLowerCase(),
      )
    );
  }
}

function graphError(reply: FastifyReply, status: number, code: string) {
  return reply.code(status).send({ error: { code, message: code } });
}

function userView(u: FixtureSeed['users'][number]) {
  return {
    id: u.id,
    userPrincipalName: u.userPrincipalName,
    displayName: u.displayName,
    accountEnabled: u.accountEnabled,
  };
}

/** `$filter=<field> eq '<value>'` — the only filter shape the connector sends. */
function eqFilter(filter: unknown, field: string): string | undefined {
  if (typeof filter !== 'string') return undefined;
  const match = new RegExp(`^${field} eq '([^']+)'$`).exec(filter.trim());
  return match?.[1];
}

function top(query: unknown, fallback = 50): number {
  const raw = Number((query as { $top?: string }).$top);
  return Number.isInteger(raw) && raw > 0 ? raw : fallback;
}

export default function microsoftFixtureRoutes(
  fastify: FastifyInstance,
  opts: MicrosoftFixtureOptions,
): void {
  const config = { ...FIXTURE_DEFAULTS, ...opts };
  const state = new FixtureState();
  const prefix = fastify.prefix;

  const pathOf = (request: FastifyRequest) =>
    request.url.split('?')[0]!.slice(prefix.length);

  fastify.addContentTypeParser(
    'application/x-www-form-urlencoded',
    { parseAs: 'string' },
    (_req, body, done) => {
      done(null, Object.fromEntries(new URLSearchParams(body as string)));
    },
  );

  // Every JSON object this fixture returns is labelled as fixture data.
  fastify.addHook('preSerialization', async (_req, _reply, payload) =>
    payload && typeof payload === 'object' && !Array.isArray(payload)
      ? { ...payload, _dataOrigin: 'DEMO_FIXTURE' }
      : payload,
  );

  // Fault injection and request recording for everything except the controls.
  fastify.addHook('preHandler', async (request, reply) => {
    const path = pathOf(request);
    if (path.startsWith('/_fixture')) return;
    state.requests.push({
      method: request.method,
      path,
      query: { ...(request.query as Record<string, unknown>) },
      body: request.body ?? null,
    });
    const key = `${request.method} ${path}`;
    const fault = state.faults.get(key);
    if (!fault) return;
    fault.remaining -= 1;
    if (fault.remaining <= 0) state.faults.delete(key);
    if (fault.delayMs) {
      await new Promise((r) => setTimeout(r, fault.delayMs));
    }
    if (fault.drop) {
      request.raw.socket.destroy();
      return reply;
    }
    if (fault.status) {
      return graphError(reply, fault.status, 'FixtureInjectedFault');
    }
  });

  // ---- fixture controls ----
  fastify.post('/_fixture/reset', () => {
    state.reset();
    return { status: 'reset' };
  });
  fastify.get('/_fixture/state', () => ({
    users: [...state.users.values()],
    riskyUsers: [...state.riskyUsers.values()],
    isolatedMachineIds: [...state.isolated],
    machineActions: state.machineActions,
    tokenRequests: state.tokenRequests,
  }));
  fastify.get('/_fixture/requests', () => ({ requests: state.requests }));
  fastify.post('/_fixture/faults', (request) => {
    const body = request.body as {
      method: string;
      path: string;
      status?: number;
      delayMs?: number;
      drop?: boolean;
      times?: number;
    };
    state.faults.set(`${body.method.toUpperCase()} ${body.path}`, {
      status: body.status,
      delayMs: body.delayMs,
      drop: body.drop,
      remaining: body.times ?? 1,
    });
    return { status: 'armed' };
  });

  // ---- Entra ID token endpoint (client-credentials only) ----
  fastify.post('/login/:tenant/oauth2/v2.0/token', (request, reply) => {
    state.tokenRequests += 1;
    const { tenant } = request.params as { tenant: string };
    const form = (request.body ?? {}) as Record<string, string>;
    if (tenant !== config.tenantId) {
      return reply.code(400).send({ error: 'invalid_request' });
    }
    if (form.grant_type !== 'client_credentials') {
      return reply.code(400).send({ error: 'unsupported_grant_type' });
    }
    if (
      form.client_id !== config.clientId ||
      form.client_secret !== config.clientSecret
    ) {
      return reply.code(401).send({ error: 'invalid_client' });
    }
    const audience: Audience | undefined =
      form.scope === GRAPH_SCOPE
        ? 'graph'
        : form.scope === DEFENDER_SCOPE
          ? 'defender'
          : undefined;
    if (!audience) return reply.code(400).send({ error: 'invalid_scope' });
    const token = `fixture.${audience}.${randomBytes(16).toString('hex')}`;
    state.tokens.set(token, {
      audience,
      expiresAt: Date.now() + config.tokenTtlSeconds * 1000,
    });
    return {
      token_type: 'Bearer',
      expires_in: config.tokenTtlSeconds,
      access_token: token,
    };
  });

  const requireToken =
    (audience: Audience) =>
    async (request: FastifyRequest, reply: FastifyReply) => {
      const token = request.headers.authorization?.replace(/^Bearer /, '');
      const entry = token ? state.tokens.get(token) : undefined;
      if (
        !entry ||
        entry.audience !== audience ||
        entry.expiresAt < Date.now()
      ) {
        await graphError(reply, 401, 'InvalidAuthenticationToken');
      }
    };

  // ---- Microsoft Graph v1.0 ----
  void fastify.register(
    (graph) => {
      graph.addHook('preHandler', requireToken('graph'));

      graph.get('/users/:id', (request, reply) => {
        const user = state.findUser((request.params as { id: string }).id);
        return user
          ? userView(user)
          : graphError(reply, 404, 'Request_ResourceNotFound');
      });

      graph.patch('/users/:id', (request, reply) => {
        const user = state.findUser((request.params as { id: string }).id);
        if (!user) return graphError(reply, 404, 'Request_ResourceNotFound');
        const body = (request.body ?? {}) as {
          accountEnabled?: unknown;
          passwordProfile?: {
            password?: unknown;
            forceChangePasswordNextSignIn?: unknown;
          };
        };
        if (typeof body.accountEnabled === 'boolean') {
          user.accountEnabled = body.accountEnabled;
        }
        if (body.passwordProfile) {
          if (typeof body.passwordProfile.password !== 'string') {
            return graphError(reply, 400, 'Request_BadRequest');
          }
          user.passwordResetAt = new Date().toISOString();
          user.forceChangePasswordNextSignIn =
            body.passwordProfile.forceChangePasswordNextSignIn === true;
        }
        return reply.code(204).send();
      });

      graph.post('/users/:id/revokeSignInSessions', (request, reply) => {
        const user = state.findUser((request.params as { id: string }).id);
        if (!user) return graphError(reply, 404, 'Request_ResourceNotFound');
        user.sessionsRevokedAt = new Date().toISOString();
        return {
          '@odata.context':
            'https://graph.microsoft.com/v1.0/$metadata#Edm.Boolean',
          value: true,
        };
      });

      graph.get('/security/incidents', (request) => ({
        value: state.incidents.slice(0, top(request.query)),
      }));
      graph.get('/security/incidents/:id', (request, reply) => {
        const { id } = request.params as { id: string };
        const incident = state.incidents.find((i) => i.id === id);
        if (!incident) return graphError(reply, 404, 'NotFound');
        const expand = (request.query as { $expand?: string }).$expand;
        return expand === 'alerts'
          ? {
              ...incident,
              alerts: state.alerts.filter((a) => a.incidentId === id),
            }
          : incident;
      });
      graph.get('/security/alerts_v2', (request) => ({
        value: state.alerts.slice(0, top(request.query)),
      }));
      graph.get('/security/alerts_v2/:id', (request, reply) => {
        const alert = state.alerts.find(
          (a) => a.id === (request.params as { id: string }).id,
        );
        return alert ?? graphError(reply, 404, 'NotFound');
      });

      graph.get('/auditLogs/signIns', (request) => {
        const query = request.query as { $filter?: string };
        const userId = eqFilter(query.$filter, 'userId');
        return {
          value: state.signIns
            .filter((s) => !userId || s.userId === userId)
            .slice(0, top(request.query)),
        };
      });

      graph.get('/identityProtection/riskyUsers/:id', (request, reply) => {
        const risky = state.riskyUsers.get(
          (request.params as { id: string }).id,
        );
        return risky ?? graphError(reply, 404, 'NotFound');
      });

      const setRiskState =
        (riskState: 'confirmedCompromised' | 'dismissed') =>
        (request: FastifyRequest, reply: FastifyReply) => {
          const { userIds } = (request.body ?? {}) as { userIds?: unknown };
          if (!Array.isArray(userIds) || userIds.length === 0) {
            return graphError(reply, 400, 'BadRequest');
          }
          for (const id of userIds) {
            const risky = state.riskyUsers.get(String(id));
            if (!risky) continue;
            risky.riskState = riskState;
            risky.riskLevel = riskState === 'dismissed' ? 'none' : 'high';
            risky.riskDetail =
              riskState === 'dismissed'
                ? 'adminDismissedAllRiskForUser'
                : 'adminConfirmedUserCompromised';
            risky.riskLastUpdatedDateTime = new Date().toISOString();
          }
          return reply.code(204).send();
        };
      graph.post(
        '/identityProtection/riskyUsers/confirmCompromised',
        setRiskState('confirmedCompromised'),
      );
      graph.post(
        '/identityProtection/riskyUsers/dismiss',
        setRiskState('dismissed'),
      );
    },
    { prefix: '/graph/v1.0' },
  );

  // ---- Defender for Endpoint API ----
  void fastify.register(
    (defender) => {
      defender.addHook('preHandler', requireToken('defender'));

      defender.get('/machines/:id', (request, reply) => {
        const machine = state.machines.get(
          (request.params as { id: string }).id,
        );
        return machine ?? graphError(reply, 404, 'ResourceNotFound');
      });

      const machineAction =
        (
          type: string,
          validate: (body: Record<string, unknown>) => boolean,
          apply?: (id: string) => void,
        ) =>
        (request: FastifyRequest, reply: FastifyReply) => {
          const { id } = request.params as { id: string };
          const machine = state.machines.get(id);
          if (!machine) return graphError(reply, 404, 'ResourceNotFound');
          const body = (request.body ?? {}) as Record<string, unknown>;
          if (typeof body.Comment !== 'string' || !validate(body)) {
            return graphError(reply, 400, 'InvalidRequestBody');
          }
          apply?.(id);
          const now = new Date().toISOString();
          const action: FixtureMachineAction = {
            id: randomUUID(),
            type,
            requestor: config.clientId,
            requestorComment: body.Comment,
            status: 'Pending',
            machineId: id,
            computerDnsName: machine.computerDnsName,
            creationDateTimeUtc: now,
            lastUpdateDateTimeUtc: now,
          };
          // The fixture completes every action at once; the real service
          // reports Pending and completes asynchronously.
          state.machineActions.push({ ...action, status: 'Succeeded' });
          return reply.code(201).send(action);
        };

      defender.post(
        '/machines/:id/isolate',
        machineAction(
          'Isolate',
          (b) => b.IsolationType === 'Full' || b.IsolationType === 'Selective',
          (id) => state.isolated.add(id),
        ),
      );
      defender.post(
        '/machines/:id/unisolate',
        machineAction(
          'Unisolate',
          () => true,
          (id) => state.isolated.delete(id),
        ),
      );
      defender.post(
        '/machines/:id/runAntiVirusScan',
        machineAction(
          'RunAntiVirusScan',
          (b) => b.ScanType === 'Quick' || b.ScanType === 'Full',
        ),
      );
      defender.post(
        '/machines/:id/collectInvestigationPackage',
        machineAction('CollectInvestigationPackage', () => true),
      );
      defender.post(
        '/machines/:id/StopAndQuarantineFile',
        machineAction(
          'StopAndQuarantineFile',
          (b) => typeof b.Sha1 === 'string' && /^[0-9a-fA-F]{40}$/.test(b.Sha1),
        ),
      );

      defender.get('/machineactions', (request) => {
        const machineId = eqFilter(
          (request.query as { $filter?: string }).$filter,
          'machineId',
        );
        return {
          value: state.machineActions
            .filter((a) => !machineId || a.machineId === machineId)
            .slice(0, top(request.query)),
        };
      });
      defender.get('/machineactions/:id', (request, reply) => {
        const action = state.machineActions.find(
          (a) => a.id === (request.params as { id: string }).id,
        );
        return action ?? graphError(reply, 404, 'ResourceNotFound');
      });
    },
    { prefix: '/defender/api' },
  );
}

/** A Fastify instance serving only this fixture under `/microsoft`, for in-process use by manar-api's tests. */
export function buildMicrosoftFixtureApp(
  options: MicrosoftFixtureOptions = {},
): FastifyInstance {
  const app = Fastify({ logger: false });
  void app.register(microsoftFixtureRoutes, {
    ...options,
    prefix: '/microsoft',
  });
  return app;
}
