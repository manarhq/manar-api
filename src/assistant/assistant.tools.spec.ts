import { describe, expect, it } from 'vitest';
import {
  ASSISTANT_TOOLS,
  READ_PATHS,
  isAllowedReadPath,
  toolSchemas,
  type AssistantSuggestion,
  type ToolContext,
} from './assistant.tools';
import { HELP_TOPICS, REASON_CODES } from './assistant.knowledge';

const ID = '11111111-2222-4333-8444-555555555555';

/** A context that records every path a tool asks for and answers 200 with `body`. */
function recordingCtx(body: unknown = { items: [] }) {
  const paths: string[] = [];
  const suggestions: AssistantSuggestion[] = [];
  const ctx: ToolContext = {
    read: (path) => {
      paths.push(path);
      return Promise.resolve({ ok: true, body });
    },
    cite: () => 1,
    seen: new Set([ID]),
    suggest: (s) => suggestions.push(s),
    locale: 'en',
    now: new Date('2026-10-09T10:00:00Z'),
  };
  return { ctx, paths, suggestions };
}

/** Valid arguments for every tool, so each one can be exercised. */
const SAMPLE_ARGS: Record<string, Record<string, unknown>> = {
  search_decisions: { outcome: 'DENY', agentId: ID, sinceHours: 48 },
  get_decision: { correlationId: ID },
  get_audit_event: { correlationId: ID, eventId: ID },
  list_pending_approvals: {},
  get_approval: { approvalId: ID },
  get_agent_activity: { agent: 'soc-response-agent' },
  get_policy_rule: { name: 'default' },
  get_incident: { incidentId: ID },
  explain_reason_code: { code: 'policy_denied' },
  help_lookup: { topic: 'add_agent' },
  prepare_for_human: { kind: 'review_approval', approvalId: ID },
};

describe('console assistant tool set', () => {
  it('is exactly the fixed read-only list (a new tool must be added here on purpose)', () => {
    expect(ASSISTANT_TOOLS.map((t) => t.name)).toEqual(
      Object.keys(SAMPLE_ARGS),
    );
  });

  it('registers no tool whose name says it changes something', () => {
    const writeVerb =
      /(approve|deny|decide|publish|kill|activate|deactivate|revoke|release|quarantine|suspend|create|update|edit|delete|set|enable|disable|invoke|execute|export)/i;
    expect(
      ASSISTANT_TOOLS.map((t) => t.name).filter((n) => writeVerb.test(n)),
    ).toEqual([]);
  });

  it('every tool, given valid arguments, reads only allowed GET paths and never a write route', async () => {
    const writeRoute =
      /\/(decide|publish|kill-switch|revoke|transitions|enrollment-tokens|export|verify|investigate|suggest|summarize|role-bindings|versions)\b|\/kill-switches/;
    for (const tool of ASSISTANT_TOOLS) {
      const { ctx, paths } = recordingCtx();
      const args = tool.params.parse(SAMPLE_ARGS[tool.name]);
      await tool.run(args as never, ctx);
      for (const path of paths) {
        expect(isAllowedReadPath(path), `${tool.name} -> ${path}`).toBe(true);
        expect(writeRoute.test(path), `${tool.name} -> ${path}`).toBe(false);
      }
    }
  });

  it('read paths refuse write routes and path tricks', () => {
    for (const path of [
      `/approvals/${ID}/decide`,
      '/kill-switches',
      '/kill-switches/platform',
      `/agents/${ID}/kill-switch`,
      `/agents/${ID}/revoke`,
      `/policies/${ID}/versions/${ID}/publish`,
      '/audit/verify',
      '/audit/investigate',
      '/evidence/export',
      '/tenant/settings',
      '/audit?x=1/../kill-switches',
      `/approvals/${ID}/../../kill-switches`,
      '/agent/v1/authorize',
    ]) {
      expect(isAllowedReadPath(path), path).toBe(false);
    }
    expect(READ_PATHS.length).toBe(7);
  });

  it('argument schemas are strict: a model cannot add tenantId or a raw path', () => {
    for (const tool of ASSISTANT_TOOLS) {
      const withTenant = tool.params.safeParse({
        ...SAMPLE_ARGS[tool.name],
        tenantId: ID,
      });
      expect(withTenant.success, tool.name).toBe(false);
      const withPath = tool.params.safeParse({
        ...SAMPLE_ARGS[tool.name],
        path: '/kill-switches',
      });
      expect(withPath.success, tool.name).toBe(false);
    }
  });

  it('ids must be UUIDs, so an id cannot smuggle a path into a read', () => {
    const getApproval = ASSISTANT_TOOLS.find((t) => t.name === 'get_approval')!;
    expect(
      getApproval.params.safeParse({ approvalId: `${ID}/decide` }).success,
    ).toBe(false);
    expect(
      getApproval.params.safeParse({ approvalId: '../kill-switches' }).success,
    ).toBe(false);
  });

  it('query values are encoded, so a filter cannot add parameters', async () => {
    const tool = ASSISTANT_TOOLS.find((t) => t.name === 'get_agent_activity')!;
    const { ctx, paths } = recordingCtx({
      items: [{ id: ID, slug: 'a&eventType=x', displayName: 'A' }],
    });
    await tool.run({ agent: 'a&eventType=x' } as never, ctx);
    expect(paths[1]).toContain(`agentId=${ID}`);
    expect(paths.every(isAllowedReadPath)).toBe(true);
  });

  it('prepare_for_human makes a suggestion and reads nothing', async () => {
    const tool = ASSISTANT_TOOLS.find((t) => t.name === 'prepare_for_human')!;
    const { ctx, paths, suggestions } = recordingCtx();
    const out = await tool.run(
      {
        kind: 'review_approval',
        approvalId: ID,
        highlight: 'approve',
      } as never,
      ctx,
    );
    expect(paths).toEqual([]);
    expect(out).toMatchObject({ buttonShown: true });
    expect(suggestions).toEqual([
      expect.objectContaining({
        type: 'highlight',
        href: `/approvals/${ID}`,
        target: 'approve-button',
      }),
    ]);
  });

  it('prepare_for_human opens only records that were read, on fixed console paths', async () => {
    const tool = ASSISTANT_TOOLS.find((t) => t.name === 'prepare_for_human')!;
    const { ctx, suggestions } = recordingCtx();
    await tool.run(
      { kind: 'open_record', record: 'agent', id: ID } as never,
      ctx,
    );
    expect(suggestions).toEqual([
      { type: 'open', label: 'Open agent', href: `/agents/${ID}` },
    ]);
    ctx.seen.clear();
    expect(
      await tool.run(
        { kind: 'open_record', record: 'agent', id: ID } as never,
        ctx,
      ),
    ).toEqual({ error: 'read_the_record_first' });
  });

  it('prepare_for_human refuses an approval id the assistant never read', async () => {
    const tool = ASSISTANT_TOOLS.find((t) => t.name === 'prepare_for_human')!;
    const { ctx, suggestions } = recordingCtx();
    ctx.seen.clear();
    const out = await tool.run(
      { kind: 'review_approval', approvalId: ID } as never,
      ctx,
    );
    expect(out).toEqual({ error: 'read_the_approval_first' });
    expect(suggestions).toEqual([]);
  });

  it('pending approvals come back riskiest first', async () => {
    const tool = ASSISTANT_TOOLS.find(
      (t) => t.name === 'list_pending_approvals',
    )!;
    const mk = (n: number, riskScore: number) => ({
      id: `${ID.slice(0, -1)}${n}`,
      riskScore,
    });
    const { ctx } = recordingCtx({ items: [mk(1, 20), mk(2, 90), mk(3, 55)] });
    const out = (await tool.run({} as never, ctx)) as {
      approvals: { riskScore: number }[];
    };
    expect(out.approvals.map((a) => a.riskScore)).toEqual([90, 55, 20]);
  });

  it('a refused read is reported as a permission error, never retried another way', async () => {
    const tool = ASSISTANT_TOOLS.find((t) => t.name === 'search_decisions')!;
    const paths: string[] = [];
    const { ctx } = recordingCtx();
    ctx.read = (path) => {
      paths.push(path);
      return Promise.resolve({ ok: false, status: 403 });
    };
    expect(await tool.run({} as never, ctx)).toEqual({
      error: 'not_permitted_for_your_role',
      status: 403,
    });
    expect(paths).toHaveLength(1);
  });

  it('tool schemas sent to the model are plain JSON schema objects', () => {
    for (const schema of toolSchemas()) {
      expect(schema.function.parameters).toMatchObject({ type: 'object' });
      expect(schema.function.parameters).not.toHaveProperty('$schema');
    }
  });

  it('curated text has both languages and no em or en dashes', () => {
    const texts = [
      ...Object.values(REASON_CODES).flatMap((b) => [b.en, b.ar]),
      ...Object.values(HELP_TOPICS).flatMap((h) => [
        h.title.en,
        h.title.ar,
        h.steps.en,
        h.steps.ar,
      ]),
    ];
    for (const text of texts) {
      expect(text.length).toBeGreaterThan(0);
      expect(text).not.toMatch(/[\u2013\u2014]/);
    }
  });
});
