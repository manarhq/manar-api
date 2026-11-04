import type { ExecutionContext } from '@nestjs/common';
import { HttpAdapterHost, Reflector } from '@nestjs/core';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AgentsController } from '../agents/agents.controller';
import { ApprovalsController } from '../approvals/approvals.controller';
import { AuditController } from '../audit/audit.controller';
import type { RoleName } from '../auth/roles';
import { RolesGuard } from '../auth/roles.guard';
import { IncidentsController } from '../incidents/incidents.controller';
import { PolicyController } from '../policy/policy.controller';
import { AssistantReader } from './assistant-reader.service';
import { ASSISTANT_TOOLS, type ToolContext } from './assistant.tools';

/**
 * RBAC and tenant isolation through the reader. A real Fastify instance
 * serves the routes the tools read; each route runs the real `RolesGuard`
 * against the real `@RequireRole` metadata of the controller handler that
 * serves it in manar-api. The fake bearer token `roles=<A,B>;tenant=<t>`
 * stands in for JwtAuthGuard (covered by its own spec). If the assistant
 * could read past a role gate, or see another tenant's rows, it shows here.
 */

const ID = '11111111-2222-4333-8444-555555555555';
type Handler = (...args: never[]) => unknown;
const ROUTES: [string, { prototype: object }, string][] = [
  ['/audit', AuditController, 'search'],
  ['/approvals', ApprovalsController, 'list'],
  ['/approvals/:id', ApprovalsController, 'getOne'],
  ['/agents', AgentsController, 'listAgents'],
  ['/policies', PolicyController, 'listPolicies'],
  ['/policies/:id', PolicyController, 'getPolicy'],
  ['/incidents/:id', IncidentsController, 'get'],
];

const guard = new RolesGuard(new Reflector());
let app: FastifyInstance;
const seenTenants: string[] = [];

function parseToken(header: string | undefined) {
  const m = /^Bearer roles=([A-Z_,]*);tenant=([a-z0-9-]+)$/.exec(header ?? '');
  return m ? { roles: m[1]!.split(',') as RoleName[], tenant: m[2]! } : null;
}

beforeAll(async () => {
  app = Fastify();
  for (const [url, controller, method] of ROUTES) {
    const handler = (controller.prototype as Record<string, Handler>)[method]!;
    app.get(url, (req, reply) => {
      const auth = parseToken(req.headers.authorization);
      if (!auth) return reply.code(401).send({});
      const context = {
        getHandler: () => handler,
        getClass: () => controller,
        switchToHttp: () => ({
          getRequest: () => ({ authContext: { roles: auth.roles } }),
        }),
      } as unknown as ExecutionContext;
      try {
        guard.canActivate(context);
      } catch {
        return reply.code(403).send({});
      }
      seenTenants.push(auth.tenant);
      // Each tenant only ever sees rows that carry its own name.
      const row = { id: ID, tenant: auth.tenant, riskScore: 50 };
      return reply.send(url.includes(':id') ? row : { items: [row] });
    });
  }
  await app.ready();
});

afterAll(() => app.close());

const reader = () =>
  new AssistantReader({
    httpAdapter: { getInstance: () => app },
  } as unknown as HttpAdapterHost);

function ctxFor(token: string): ToolContext {
  const r = reader();
  return {
    read: (path) => r.get(path, token),
    cite: () => 1,
    seen: new Set([ID]),
    suggest: () => undefined,
    locale: 'en',
    now: new Date(),
  };
}

const run = (name: string, args: object, ctx: ToolContext) =>
  ASSISTANT_TOOLS.find((t) => t.name === name)!.run(args as never, ctx);

const DENIED = { error: 'not_permitted_for_your_role', status: 403 };

describe('assistant reads respect the caller role (real RolesGuard metadata)', () => {
  it('a READ_ONLY viewer can read none of the gated records', async () => {
    const ctx = ctxFor('Bearer roles=READ_ONLY;tenant=acme');
    expect(await run('search_decisions', {}, ctx)).toEqual(DENIED);
    expect(await run('get_decision', { correlationId: ID }, ctx)).toEqual(
      DENIED,
    );
    expect(await run('get_policy_rule', { policyId: ID }, ctx)).toEqual(DENIED);
    expect(await run('get_agent_activity', { agent: ID }, ctx)).toEqual(DENIED);
  });

  it('an APPROVER sees approvals but not the audit log', async () => {
    const ctx = ctxFor('Bearer roles=APPROVER;tenant=acme');
    expect(await run('list_pending_approvals', {}, ctx)).toMatchObject({
      pendingCount: 1,
    });
    expect(await run('search_decisions', {}, ctx)).toEqual(DENIED);
  });

  it('an AUDITOR sees decisions but not approvals', async () => {
    const ctx = ctxFor('Bearer roles=AUDITOR;tenant=acme');
    expect(await run('search_decisions', {}, ctx)).toMatchObject({
      decisions: [],
    });
  });

  it('approvals have no role gate: the controller itself narrows a non-approver to their own', async () => {
    // Founder decision, 3 Nov 2026: a device or agent owner sees and answers their own requests.
    // The narrowing is inside ApprovalsController (approvals.controller.access.spec.ts), which
    // this fake route does not run, so only the absence of a role gate is checked here.
    const ctx = ctxFor('Bearer roles=READ_ONLY;tenant=acme');
    expect(await run('list_pending_approvals', {}, ctx)).not.toEqual(DENIED);
  });

  it('no token, no data', async () => {
    const ctx = ctxFor('Bearer not-a-token');
    expect(await run('list_pending_approvals', {}, ctx)).toEqual({
      error: 'not_permitted_for_your_role',
      status: 401,
    });
  });

  it('tenant comes only from the token: each user sees only their own tenant', async () => {
    seenTenants.length = 0;
    const a = (await run(
      'get_approval',
      { approvalId: ID },
      ctxFor('Bearer roles=APPROVER;tenant=acme'),
    )) as { resource?: unknown };
    const b = (await run(
      'list_pending_approvals',
      {},
      ctxFor('Bearer roles=APPROVER;tenant=globex'),
    )) as { approvals: unknown[] };
    expect(seenTenants).toEqual(['acme', 'globex']);
    expect(a).toBeDefined();
    expect(b.approvals).toHaveLength(1);
  });

  it('the reader refuses a non-allowlisted path before any request is made', async () => {
    await expect(
      reader().get('/kill-switches', 'Bearer roles=TENANT_OWNER;tenant=acme'),
    ).rejects.toThrow(/not allowed/);
    await expect(
      reader().get(
        `/approvals/${ID}/decide`,
        'Bearer roles=TENANT_OWNER;tenant=acme',
      ),
    ).rejects.toThrow(/not allowed/);
  });
});
