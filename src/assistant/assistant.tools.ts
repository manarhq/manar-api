import { z } from 'zod';
import {
  HELP_TOPICS,
  HELP_TOPIC_KEYS,
  REASON_CODES,
  type AssistantLocale,
} from './assistant.knowledge';

/**
 * The console assistant's complete, fixed tool set (manar-api ADR-0008).
 *
 * Read-only by construction: a tool gets a `ToolContext`, whose only way to
 * reach tenant data is `read(path)`, an in-process GET through manar-api's
 * own HTTP routes with the signed-in human's bearer token (so the same
 * JwtAuthGuard, RolesGuard and tenant resolution run as for the console).
 * `read` refuses any path outside `READ_PATHS`. No tool holds a service, a
 * Prisma client or another credential. "Prepare" is a suggestion the
 * console renders as a button; it changes nothing.
 */

export type ReadResult =
  { ok: true; body: unknown } | { ok: false; status: number };

export type SourceKind =
  | 'decision'
  | 'audit_event'
  | 'approval'
  | 'agent'
  | 'policy'
  | 'incident'
  | 'help'
  /** A console list page, cited when a list read returns nothing. */
  | 'page';

export interface AssistantSource {
  ref: number;
  kind: SourceKind;
  id: string;
  label: string;
  /** Console path without the locale prefix. */
  href: string;
}

export type AssistantSuggestion =
  | { type: 'open'; label: string; href: string }
  | {
      type: 'highlight';
      label: string;
      href: string;
      target: 'approve-button' | 'deny-button';
    }
  | { type: 'draft'; label: string; href: string; draft: string };

export interface ToolContext {
  read(path: string): Promise<ReadResult>;
  /** Registers a record the answer may cite; returns its reference number. */
  cite(source: Omit<AssistantSource, 'ref'>): number;
  /** Ids (any kind) the assistant has actually read in this request. */
  seen: Set<string>;
  suggest(suggestion: AssistantSuggestion): void;
  locale: AssistantLocale;
  now: Date;
}

export interface AssistantTool {
  name: string;
  description: string;
  params: z.ZodObject;
  run(params: never, ctx: ToolContext): unknown;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const uuid = z.string().regex(UUID, 'must be a UUID');
const UUID_PART = '[0-9a-fA-F-]{36}';

/** Every path a tool may read. GET only; anything else is refused before dispatch. */
export const READ_PATHS: readonly RegExp[] = [
  /^\/audit\?[^/]*$/,
  /^\/approvals\?[^/]*$/,
  new RegExp(`^/approvals/${UUID_PART}$`),
  /^\/agents\?[^/]*$/,
  /^\/policies\?[^/]*$/,
  new RegExp(`^/policies/${UUID_PART}$`),
  new RegExp(`^/incidents/${UUID_PART}$`),
];

export function isAllowedReadPath(path: string): boolean {
  return READ_PATHS.some((re) => re.test(path));
}

const qs = (params: Record<string, string | number | undefined>) =>
  new URLSearchParams(
    Object.entries(params)
      .filter(([, v]) => v !== undefined)
      .map(([k, v]) => [k, String(v)]),
  ).toString();

/** Bounded copy: strings clipped, arrays capped, depth limited. Keeps the model's context small. */
export function clip(value: unknown, depth = 0): unknown {
  if (typeof value === 'string')
    return value.length > 400 ? `${value.slice(0, 400)}...` : value;
  if (depth > 5) return '[nested]';
  if (Array.isArray(value))
    return value.slice(0, 20).map((v) => clip(v, depth + 1));
  if (value && typeof value === 'object')
    return Object.fromEntries(
      Object.entries(value)
        .slice(0, 40)
        .map(([k, v]) => [k, clip(v, depth + 1)]),
    );
  return value;
}

const forbidden = (status: number) => ({
  error:
    status === 401 || status === 403
      ? 'not_permitted_for_your_role'
      : status === 404
        ? 'not_found'
        : 'read_failed',
  status,
});

const OUTCOME_BY_EVENT: Record<string, string> = {
  'authorization.allowed': 'ALLOW',
  'authorization.denied': 'DENY',
  'authorization.pending_approval': 'APPROVAL_REQUIRED',
};
const DECISION_EVENTS = Object.keys(OUTCOME_BY_EVENT).join(',');

interface AuditItem {
  eventId: string;
  correlationId: string;
  eventType: string;
  timestamp: string;
  sequence?: number;
  actor?: unknown;
  agentId?: string;
  taskId?: string;
  toolId?: string;
  actionId?: string;
  decision?: string;
  riskScore?: number;
  data?: Record<string, unknown> | null;
}

const auditItems = (body: unknown): AuditItem[] =>
  ((body as { items?: AuditItem[] })?.items ?? []).filter(
    (i) => i && typeof i.eventId === 'string',
  );

const sinceIso = (ctx: ToolContext, hours: number) =>
  new Date(ctx.now.getTime() - hours * 3_600_000).toISOString();

function explain(code: unknown, locale: AssistantLocale): string | undefined {
  return typeof code === 'string' ? REASON_CODES[code]?.[locale] : undefined;
}

function decisionRow(item: AuditItem, ctx: ToolContext) {
  const outcome = OUTCOME_BY_EVENT[item.eventType];
  for (const id of [item.correlationId, item.eventId, item.agentId])
    if (id) ctx.seen.add(id);
  const ref = ctx.cite({
    kind: outcome ? 'decision' : 'audit_event',
    id: item.eventId,
    label: outcome ? `${outcome} ${item.eventId.slice(0, 8)}` : item.eventType,
    href: `/audit/${item.eventId}`,
  });
  const data = item.data ?? {};
  return {
    ref,
    eventId: item.eventId,
    correlationId: item.correlationId,
    time: item.timestamp,
    eventType: item.eventType,
    ...(outcome ? { outcome } : {}),
    agentId: item.agentId,
    taskId: item.taskId,
    toolId: item.toolId,
    actionId: item.actionId,
    riskScore: item.riskScore ?? data.riskScore,
    reason: data.reason,
    reasonMeaning: explain(data.reason, ctx.locale),
    matchedRule: clip(data.matchedRule),
    policyVersionId: data.policyVersionId,
    approvalRequestId: data.approvalRequestId,
  };
}

async function trail(
  ctx: ToolContext,
  correlationId: string,
  eventId: string | undefined,
  decisionOnly: boolean,
) {
  const res = await ctx.read(`/audit?${qs({ correlationId, limit: 50 })}`);
  if (!res.ok) return forbidden(res.status);
  const items = auditItems(res.body).sort(
    (a, b) => (a.sequence ?? 0) - (b.sequence ?? 0),
  );
  if (items.length === 0) return { error: 'not_found' };
  const events = items.map((i) => ({
    ...decisionRow(i, ctx),
    actor: i.actor,
    ...(eventId === i.eventId || !decisionOnly
      ? { details: clip(i.data) }
      : {}),
  }));
  const approvals = new Map<string, number>();
  for (const e of events) {
    const id = e.approvalRequestId;
    if (typeof id === 'string' && UUID.test(id) && !approvals.has(id)) {
      ctx.seen.add(id);
      approvals.set(
        id,
        ctx.cite({
          kind: 'approval',
          id,
          label: id.slice(0, 8),
          href: `/approvals/${id}`,
        }),
      );
    }
  }
  const related = [...approvals].map(([approvalId, ref]) => ({
    ref,
    approvalId,
  }));
  return decisionOnly
    ? {
        decision: events.find((e) => 'outcome' in e) ?? null,
        relatedApprovals: related,
        timeline: events,
      }
    : { events, relatedApprovals: related };
}

const searchDecisions: AssistantTool = {
  name: 'search_decisions',
  description:
    'Find recent authorization decisions (ALLOW, DENY, APPROVAL_REQUIRED) for agent actions, newest first. Filter by outcome, agent id and time window.',
  params: z
    .object({
      outcome: z.enum(['ALLOW', 'DENY', 'APPROVAL_REQUIRED']).optional(),
      agentId: uuid.optional(),
      sinceHours: z.number().int().min(1).max(720).optional(),
      limit: z.number().int().min(1).max(20).optional(),
    })
    .strict(),
  async run(
    p: {
      outcome?: string;
      agentId?: string;
      sinceHours?: number;
      limit?: number;
    },
    ctx,
  ) {
    const eventType = p.outcome
      ? Object.keys(OUTCOME_BY_EVENT).find(
          (k) => OUTCOME_BY_EVENT[k] === p.outcome,
        )
      : DECISION_EVENTS;
    const res = await ctx.read(
      `/audit?${qs({
        eventType,
        agentId: p.agentId,
        from: sinceIso(ctx, p.sinceHours ?? 24),
        limit: p.limit ?? 10,
      })}`,
    );
    if (!res.ok) return forbidden(res.status);
    const decisions = auditItems(res.body).map((i) => decisionRow(i, ctx));
    return decisions.length > 0
      ? { decisions }
      : { decisions, searchedRef: citePage(ctx, 'audit') };
  },
};

const getDecision: AssistantTool = {
  name: 'get_decision',
  description:
    'Explain one decision: its outcome, reason code and meaning, matched policy rule, risk score, and what happened after (approval, execution). Takes the correlationId from a decision or audit event.',
  params: z.object({ correlationId: uuid }).strict(),
  run: (p: { correlationId: string }, ctx) =>
    trail(ctx, p.correlationId, undefined, true),
};

const getAuditEvent: AssistantTool = {
  name: 'get_audit_event',
  description:
    'Details of an audit event and every event that shares its correlationId, in order. Takes correlationId and optionally the eventId.',
  params: z.object({ correlationId: uuid, eventId: uuid.optional() }).strict(),
  run: (p: { correlationId: string; eventId?: string }, ctx) =>
    trail(ctx, p.correlationId, p.eventId, false),
};

interface ApprovalItem {
  id: string;
  agentId?: string;
  toolId?: string;
  actionId?: string;
  resource?: string;
  riskScore?: number;
  requestedAt?: string;
  expiresAt?: string;
  status?: string;
}

/** Cites a console list page, so "nothing found" still links to where the operator can check. */
const citePage = (ctx: ToolContext, page: 'audit' | 'approvals') =>
  ctx.cite({ kind: 'page', id: page, label: page, href: `/${page}` });

const citeApproval = (ctx: ToolContext, a: ApprovalItem) => {
  ctx.seen.add(a.id);
  if (a.agentId) ctx.seen.add(a.agentId);
  return ctx.cite({
    kind: 'approval',
    id: a.id,
    label: a.id.slice(0, 8),
    href: `/approvals/${a.id}`,
  });
};

const listPendingApprovals: AssistantTool = {
  name: 'list_pending_approvals',
  description:
    'Approval requests waiting for a human decision, sorted riskiest first (highest risk score).',
  params: z
    .object({ limit: z.number().int().min(1).max(20).optional() })
    .strict(),
  async run(p: { limit?: number }, ctx) {
    const res = await ctx.read(
      `/approvals?${qs({ status: 'PENDING', limit: 100 })}`,
    );
    if (!res.ok) return forbidden(res.status);
    const items = ((res.body as { items?: ApprovalItem[] })?.items ?? [])
      .filter((a) => a && typeof a.id === 'string')
      .sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0));
    return {
      pendingCount: items.length,
      ...(items.length === 0 ? { queueRef: citePage(ctx, 'approvals') } : {}),
      approvals: items.slice(0, p.limit ?? 10).map((a) => ({
        ref: citeApproval(ctx, a),
        approvalId: a.id,
        agentId: a.agentId,
        toolId: a.toolId,
        actionId: a.actionId,
        resource: clip(a.resource),
        riskScore: a.riskScore,
        requestedAt: a.requestedAt,
        expiresAt: a.expiresAt,
      })),
    };
  },
};

const getApproval: AssistantTool = {
  name: 'get_approval',
  description:
    'One approval request: the exact action and parameters under review, risk breakdown (deterministic and AI advisory, separately), why approval is required, expiry and decisions so far.',
  params: z.object({ approvalId: uuid }).strict(),
  async run(p: { approvalId: string }, ctx) {
    const res = await ctx.read(`/approvals/${p.approvalId}`);
    if (!res.ok) return forbidden(res.status);
    const a = res.body as ApprovalItem & Record<string, unknown>;
    return {
      ref: citeApproval(ctx, { ...a, id: p.approvalId }),
      approvalId: p.approvalId,
      status: a.status,
      agentId: a.agentId,
      taskId: a.taskId,
      actionId: a.actionId,
      resource: clip(a.resource),
      params: clip(a.params),
      redactedKeyPaths: clip(a.redactedKeyPaths),
      riskScore: a.riskScore,
      deterministicRiskScore: a.deterministicRiskScore,
      aiAdvisoryScore: a.aiAdvisoryScore,
      taskRiskCeiling: a.taskRiskCeiling,
      requiredReason: a.requiredReason,
      requiredReasonMeaning: explain(a.requiredReason, ctx.locale),
      deterministicReasonCodes: clip(a.deterministicReasonCodes),
      aiAdvisoryReasonCodes: clip(a.aiAdvisoryReasonCodes),
      expectedEffect: clip(a.expectedEffect),
      requestedAt: a.requestedAt,
      expiresAt: a.expiresAt,
      decisions: clip(a.decisions),
    };
  },
};

interface AgentItem {
  id: string;
  slug?: string;
  displayName?: string;
  status?: string;
}

const getAgentActivity: AssistantTool = {
  name: 'get_agent_activity',
  description:
    'What one agent did in a time window: counts of decisions by outcome, actions used, and its latest events. `agent` is the agent id, slug or display name.',
  params: z
    .object({
      agent: z.string().min(1).max(120),
      sinceHours: z.number().int().min(1).max(720).optional(),
    })
    .strict(),
  async run(p: { agent: string; sinceHours?: number }, ctx) {
    let agent: AgentItem | undefined;
    const list = await ctx.read(`/agents?${qs({ limit: 100 })}`);
    if (list.ok) {
      const needle = p.agent.trim().toLowerCase();
      agent = ((list.body as { items?: AgentItem[] })?.items ?? []).find(
        (a) =>
          a.id === p.agent ||
          a.slug?.toLowerCase() === needle ||
          a.displayName?.toLowerCase() === needle,
      );
    }
    if (!agent && UUID.test(p.agent)) agent = { id: p.agent };
    if (!agent)
      return list.ok
        ? { error: 'agent_not_found' }
        : {
            ...forbidden(list.status),
            hint: 'Your role cannot list agents; ask with the agent id.',
          };

    const hours = p.sinceHours ?? 24;
    const res = await ctx.read(
      `/audit?${qs({ agentId: agent.id, from: sinceIso(ctx, hours), limit: 100 })}`,
    );
    if (!res.ok) return forbidden(res.status);
    const items = auditItems(res.body);
    const count = (key: (i: AuditItem) => string | undefined) =>
      items.reduce<Record<string, number>>((acc, i) => {
        const k = key(i);
        if (k) acc[k] = (acc[k] ?? 0) + 1;
        return acc;
      }, {});
    ctx.seen.add(agent.id);
    return {
      agent: {
        ref: ctx.cite({
          kind: 'agent',
          id: agent.id,
          label: agent.displayName ?? agent.slug ?? agent.id.slice(0, 8),
          href: `/agents/${agent.id}`,
        }),
        id: agent.id,
        slug: agent.slug,
        displayName: agent.displayName,
        status: agent.status,
      },
      windowHours: hours,
      eventCount: items.length,
      countsTruncatedAt100: items.length >= 100,
      byOutcome: count((i) => OUTCOME_BY_EVENT[i.eventType]),
      byEventType: count((i) => i.eventType),
      byAction: count((i) => i.actionId),
      latest: items.slice(0, 8).map((i) => decisionRow(i, ctx)),
    };
  },
};

const getPolicyRule: AssistantTool = {
  name: 'get_policy_rule',
  description:
    'Read a policy and the rules of its published version. Give policyId, or a name to search for; with neither, lists the policies.',
  params: z
    .object({ policyId: uuid.optional(), name: z.string().max(120).optional() })
    .strict(),
  async run(p: { policyId?: string; name?: string }, ctx) {
    interface Policy {
      id: string;
      name?: string;
      currentVersion?: Record<string, unknown> | null;
    }
    const shape = (pol: Policy, withRules: boolean) => {
      ctx.seen.add(pol.id);
      return {
        ref: ctx.cite({
          kind: 'policy',
          id: pol.id,
          label: pol.name ?? pol.id.slice(0, 8),
          href: `/policies/${pol.id}`,
        }),
        policyId: pol.id,
        name: pol.name,
        publishedVersion: pol.currentVersion
          ? {
              id: pol.currentVersion.id,
              version: pol.currentVersion.version,
              status: pol.currentVersion.status,
              ...(withRules
                ? { content: clip(pol.currentVersion.content) }
                : {}),
            }
          : null,
      };
    };
    if (p.policyId) {
      const res = await ctx.read(`/policies/${p.policyId}`);
      if (!res.ok) return forbidden(res.status);
      return shape({ ...(res.body as Policy), id: p.policyId }, true);
    }
    const res = await ctx.read(`/policies?${qs({ limit: 50 })}`);
    if (!res.ok) return forbidden(res.status);
    const all = ((res.body as { items?: Policy[] })?.items ?? []).filter(
      (pol) => pol && typeof pol.id === 'string',
    );
    const needle = p.name?.trim().toLowerCase();
    const hits = needle
      ? all.filter((pol) => pol.name?.toLowerCase().includes(needle))
      : all;
    return {
      policies: hits.slice(0, 10).map((pol) => shape(pol, hits.length <= 2)),
    };
  },
};

const getIncident: AssistantTool = {
  name: 'get_incident',
  description:
    'One incident: title, severity, status, description and related correlation ids.',
  params: z.object({ incidentId: uuid }).strict(),
  async run(p: { incidentId: string }, ctx) {
    const res = await ctx.read(`/incidents/${p.incidentId}`);
    if (!res.ok) return forbidden(res.status);
    const i = res.body as Record<string, unknown>;
    ctx.seen.add(p.incidentId);
    return {
      ref: ctx.cite({
        kind: 'incident',
        id: p.incidentId,
        label:
          typeof i.title === 'string'
            ? i.title.slice(0, 60)
            : p.incidentId.slice(0, 8),
        href: `/incidents/${p.incidentId}`,
      }),
      ...(clip(i) as Record<string, unknown>),
    };
  },
};

const explainReasonCode: AssistantTool = {
  name: 'explain_reason_code',
  description:
    "Plain meaning of a decision reason code such as policy_denied or agent_kill_switch_active, from Manar's curated catalog.",
  params: z.object({ code: z.string().regex(/^[a-z_]{2,64}$/) }).strict(),
  run(p: { code: string }, ctx) {
    const meaning = explain(p.code, ctx.locale);
    return meaning
      ? { code: p.code, meaning }
      : { code: p.code, error: 'not_in_catalog' };
  },
};

const helpLookup: AssistantTool = {
  name: 'help_lookup',
  description: `Curated how-to steps for the console. Topics: ${HELP_TOPIC_KEYS.join(', ')}.`,
  params: z.object({ topic: z.enum(HELP_TOPIC_KEYS) }).strict(),
  run(p: { topic: string }, ctx) {
    const topic = HELP_TOPICS[p.topic]!;
    return {
      ref: ctx.cite({
        kind: 'help',
        id: p.topic,
        label: topic.title[ctx.locale],
        href: topic.href,
      }),
      title: topic.title[ctx.locale],
      steps: topic.steps[ctx.locale],
    };
  },
};

/** Console sections `prepare_for_human` may open. */
const PAGES = {
  overview: '/overview',
  agents: '/agents',
  tasks: '/tasks',
  approvals: '/approvals',
  policies: '/policies',
  audit: '/audit',
  incidents: '/incidents',
  tools: '/tools',
  users: '/users',
  ai_systems: '/ai-systems',
} as const;

const RECORDS = {
  agent: '/agents/',
  approval: '/approvals/',
  policy: '/policies/',
  incident: '/incidents/',
  audit_event: '/audit/',
} as const;
type RecordKind = keyof typeof RECORDS;

const LABELS: Record<string, Record<AssistantLocale, string>> = {
  open: { en: 'Open page', ar: 'فتح الصفحة' },
  agent: { en: 'Open agent', ar: 'فتح الوكيل' },
  approval: { en: 'Open approval', ar: 'فتح طلب الموافقة' },
  policy: { en: 'Open policy', ar: 'فتح السياسة' },
  incident: { en: 'Open incident', ar: 'فتح الحادثة' },
  audit_event: { en: 'Open audit event', ar: 'فتح حدث التدقيق' },
  review: { en: 'Review and decide yourself', ar: 'راجع وقرر بنفسك' },
  draft: {
    en: 'Open policy with this draft',
    ar: 'فتح السياسة مع هذه المسودة',
  },
};

const prepareForHuman: AssistantTool = {
  name: 'prepare_for_human',
  description:
    'You cannot change anything. When the operator wants something done, use this to put a button in front of them. kind=open_record takes them to one record (an agent page holds its kill switch); kind=review_approval opens an approval with the Approve or Deny button highlighted (they still decide and submit); kind=draft_policy_change shows a draft rule for them to copy into a new policy version; kind=open_page opens a console section. Only ids you have read in this conversation are accepted. The button is only shown, nothing is opened or changed.',
  params: z
    .object({
      kind: z.enum([
        'open_record',
        'review_approval',
        'draft_policy_change',
        'open_page',
      ]),
      record: z.enum(Object.keys(RECORDS) as [RecordKind]).optional(),
      id: uuid.optional(),
      page: z.enum(Object.keys(PAGES) as [keyof typeof PAGES]).optional(),
      approvalId: uuid.optional(),
      highlight: z.enum(['approve', 'deny']).optional(),
      policyId: uuid.optional(),
      draft: z.string().min(1).max(4000).optional(),
    })
    .strict(),
  run(
    p: {
      kind:
        'open_record' | 'review_approval' | 'draft_policy_change' | 'open_page';
      record?: RecordKind;
      id?: string;
      page?: keyof typeof PAGES;
      approvalId?: string;
      highlight?: 'approve' | 'deny';
      policyId?: string;
      draft?: string;
    },
    ctx,
  ) {
    const unread = (id: string | undefined) => !id || !ctx.seen.has(id);
    if (p.kind === 'open_record') {
      if (!p.record) return { error: 'record_required' };
      if (unread(p.id)) return { error: 'read_the_record_first' };
      ctx.suggest({
        type: 'open',
        label: LABELS[p.record]![ctx.locale],
        href: `${RECORDS[p.record]}${p.id}`,
      });
    } else if (p.kind === 'open_page') {
      if (!p.page) return { error: 'page_required' };
      ctx.suggest({
        type: 'open',
        label: LABELS.open![ctx.locale],
        href: PAGES[p.page],
      });
    } else if (p.kind === 'review_approval') {
      if (unread(p.approvalId)) return { error: 'read_the_approval_first' };
      ctx.suggest({
        type: 'highlight',
        label: LABELS.review![ctx.locale],
        href: `/approvals/${p.approvalId}`,
        target: p.highlight === 'deny' ? 'deny-button' : 'approve-button',
      });
    } else {
      if (!p.draft) return { error: 'draft_required' };
      if (p.policyId && unread(p.policyId))
        return { error: 'read_the_policy_first' };
      ctx.suggest({
        type: 'draft',
        label: LABELS.draft![ctx.locale],
        href: p.policyId ? `/policies/${p.policyId}` : '/policies',
        draft: p.draft,
      });
    }
    return {
      buttonShown: true,
      note: 'A button is now shown under your answer. Nothing was opened or changed. Tell the operator to use the button and act on that page themselves.',
    };
  },
};

export const ASSISTANT_TOOLS: readonly AssistantTool[] = Object.freeze([
  searchDecisions,
  getDecision,
  getAuditEvent,
  listPendingApprovals,
  getApproval,
  getAgentActivity,
  getPolicyRule,
  getIncident,
  explainReasonCode,
  helpLookup,
  prepareForHuman,
]);

/** OpenAI-style `tools` array sent to the model. */
export function toolSchemas() {
  return ASSISTANT_TOOLS.map((t) => {
    const parameters = z.toJSONSchema(t.params) as Record<string, unknown>;
    delete parameters.$schema;
    return {
      type: 'function' as const,
      function: { name: t.name, description: t.description, parameters },
    };
  });
}
