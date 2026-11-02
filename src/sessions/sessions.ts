/**
 * Agent sessions (insight track): audit events grouped per device and tool, and a redacted copy
 * for sharing. Pure functions, no database, so the rules are testable and deterministic.
 *
 * A session id comes from the tool's own hook input when it gave one (`source: 'hook'`). Events
 * without one are grouped by time gap (`source: 'gap'`: a new session starts after 30 quiet
 * minutes) and the console says so.
 */
export const SESSION_GAP_MS = 30 * 60 * 1000;
const MAX_STEPS = 1000;

export type StepKind =
  'command' | 'file' | 'site' | 'tool' | 'approval' | 'secret';

export interface RawEvent {
  id: string;
  eventType: string;
  timestamp: Date;
  data: Record<string, unknown>;
}

export interface Step {
  at: string;
  kind: StepKind;
  /** `shell`, `read`, `edit`, `webfetch`, `mcp`, ... as the tool reported it. */
  action: string;
  /** The command, file path, URL, MCP call or secret path (masked by the device). */
  label: string;
  decision?: 'ALLOW' | 'DENY' | 'APPROVAL_REQUIRED';
  /** For `kind: approval` and a JAIL site ask: what the person answered, or nobody did. */
  outcome?: 'approved' | 'denied' | 'expired';
  blocked?: boolean;
}

export interface Session {
  id: string;
  hostId: string;
  toolId: string;
  source: 'hook' | 'gap';
  startedAt: string;
  endedAt: string;
  counts: {
    commands: number;
    files: number;
    sites: number;
    tools: number;
    approvals: number;
    secrets: number;
    blocked: number;
  };
  steps: Step[];
}

const str = (v: unknown): string => (typeof v === 'string' ? v : '');

/** `shell` -> command, `read`/`edit` -> file, `webfetch` -> site, everything else -> tool. */
/** A JAIL question: may this tool reach this site? (manar-edge jail/ask) */
export const SITE_CONNECT_ACTION = 'site.connect';

const OUTCOME: Record<string, Step['outcome']> = {
  'approval.approved': 'approved',
  'approval.denied': 'denied',
  'approval.expired': 'expired',
};

export function kindOfAction(actionId: string): StepKind {
  const a = actionId.toLowerCase();
  if (a === 'shell' || a === 'bash') return 'command';
  if (['read', 'edit', 'write', 'multiedit', 'glob', 'grep', 'ls'].includes(a))
    return 'file';
  if (a === 'webfetch' || a === 'websearch') return 'site';
  return 'tool';
}

interface Norm {
  /** Who called the device's relay (`uid:1000`): two accounts never share a session. */
  caller: string;
  at: Date;
  hostId: string;
  toolId: string;
  sessionId: string;
  step: Step;
  approvalId?: string;
}

function normalise(events: readonly RawEvent[]): Norm[] {
  const out: Norm[] = [];
  const approvals = new Map<string, RawEvent>();
  for (const e of events) {
    if (OUTCOME[e.eventType]) {
      // Device approvals carry hostApprovalId; task approvals approvalRequestId.
      const id =
        str(e.data.hostApprovalId) ||
        str(e.data.approvalRequestId) ||
        str(e.data.approvalId);
      if (id) approvals.set(id, e);
    }
  }
  for (const e of events) {
    const d = e.data;
    const hostId = str(d.hostId);
    const toolId = str(d.toolId);
    if (!hostId || !toolId) continue;
    const base = {
      at: e.timestamp,
      hostId,
      toolId,
      caller: str(d.caller),
      sessionId: str(d.sessionId),
    };
    if (e.eventType === 'host.action_decided') {
      const action = str(d.actionId);
      const decision = str(d.decision) as Step['decision'];
      out.push({
        ...base,
        step: {
          at: e.timestamp.toISOString(),
          kind: kindOfAction(action),
          action,
          label: str(d.resource),
          decision,
          blocked: decision === 'DENY',
        },
      });
      const approvalId = str(d.approvalId);
      const res = approvalId ? approvals.get(approvalId) : undefined;
      if (res) {
        out.push({
          ...base,
          at: res.timestamp,
          approvalId,
          step: {
            at: res.timestamp.toISOString(),
            kind: 'approval',
            action,
            label: str(d.resource),
            outcome: OUTCOME[res.eventType],
          },
        });
      }
    } else if (
      OUTCOME[e.eventType] &&
      str(d.actionId) === SITE_CONNECT_ACTION
    ) {
      // A JAIL site question; the site name is added by the loader (`resource`).
      const outcome = OUTCOME[e.eventType];
      out.push({
        ...base,
        step: {
          at: e.timestamp.toISOString(),
          kind: 'site',
          action: SITE_CONNECT_ACTION,
          label: str(d.resource),
          decision: 'APPROVAL_REQUIRED',
          outcome,
          blocked: outcome !== 'approved',
        },
      });
    } else if (
      e.eventType === 'secret.touched' ||
      e.eventType === 'secret.vault.denied'
    ) {
      out.push({
        ...base,
        step: {
          at: e.timestamp.toISOString(),
          kind: 'secret',
          action: str(d.pathClass) || 'secret',
          label: str(d.maskedPath),
          blocked: d.blocked === true || e.eventType === 'secret.vault.denied',
        },
      });
    }
  }
  return out;
}

function sessionId(
  hostId: string,
  toolId: string,
  source: 'hook' | 'gap',
  key: string,
): string {
  return Buffer.from(JSON.stringify([hostId, toolId, source, key])).toString(
    'base64url',
  );
}

/** Hook session ids are `hook`/id; gap session ids carry the first event's time. */
export function parseSessionId(id: string): {
  hostId: string;
  toolId: string;
  source: 'hook' | 'gap';
  key: string;
} | null {
  try {
    const v: unknown = JSON.parse(
      Buffer.from(id, 'base64url').toString('utf8'),
    );
    if (
      Array.isArray(v) &&
      v.length === 4 &&
      v.every((x) => typeof x === 'string') &&
      (v[2] === 'hook' || v[2] === 'gap')
    ) {
      const [hostId, toolId, source, key] = v;
      return {
        hostId: hostId!,
        toolId: toolId!,
        source: source,
        key: key!,
      };
    }
  } catch {
    /* fall through */
  }
  return null;
}

function build(
  hostId: string,
  toolId: string,
  source: 'hook' | 'gap',
  key: string,
  items: Norm[],
): Session {
  items.sort((a, b) => a.at.getTime() - b.at.getTime());
  const steps = items.map((i) => i.step);
  const count = (k: StepKind) => steps.filter((s) => s.kind === k).length;
  return {
    id: sessionId(hostId, toolId, source, key),
    hostId,
    toolId,
    source,
    startedAt: steps[0]!.at,
    endedAt: steps[steps.length - 1]!.at,
    counts: {
      commands: count('command'),
      files: count('file'),
      sites: count('site'),
      tools: count('tool'),
      // Every question put to a person: WARDEN approvals and JAIL site asks.
      approvals: steps.filter((s) => s.outcome).length,
      secrets: count('secret'),
      blocked: steps.filter((s) => s.blocked).length,
    },
    steps: steps.slice(0, MAX_STEPS),
  };
}

/** Newest session first. */
export function groupSessions(events: readonly RawEvent[]): Session[] {
  const norm = normalise(events);
  const byPair = new Map<string, Norm[]>();
  for (const n of norm) {
    const k = `${n.hostId}|${n.toolId}|${n.caller}`;
    (byPair.get(k) ?? byPair.set(k, []).get(k)!).push(n);
  }
  const sessions: Session[] = [];
  for (const items of byPair.values()) {
    const { hostId, toolId, caller } = items[0]!;
    const hooked = new Map<string, Norm[]>();
    const loose: Norm[] = [];
    for (const n of items) {
      if (n.sessionId)
        (
          hooked.get(n.sessionId) ??
          hooked.set(n.sessionId, []).get(n.sessionId)!
        ).push(n);
      else loose.push(n);
    }
    // Hook sessions as time ranges, sorted by start with a running maximum of their ends, so each
    // id-less event finds its session by binary search instead of scanning them all.
    const bounds = [...hooked.entries()]
      .map(([id, ns]) => {
        const ts = ns.map((n) => n.at.getTime());
        return { id, from: Math.min(...ts), to: Math.max(...ts), maxTo: 0 };
      })
      .sort((a, b) => a.from - b.from);
    bounds.forEach((b, k) => {
      b.maxTo = Math.max(b.to, bounds[k - 1]?.maxTo ?? 0);
    });
    const rest: Norm[] = [];
    for (const n of loose) {
      const t = n.at.getTime();
      let lo = 0;
      let hi = bounds.length - 1;
      let at = -1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (bounds[mid]!.from <= t) {
          at = mid;
          lo = mid + 1;
        } else hi = mid - 1;
      }
      let found: (typeof bounds)[number] | undefined;
      // Stops as soon as no earlier session can still be open at t.
      for (let k = at; k >= 0 && bounds[k]!.maxTo >= t; k--) {
        if (bounds[k]!.to >= t) {
          found = bounds[k];
          break;
        }
      }
      if (found) hooked.get(found.id)!.push(n);
      else rest.push(n);
    }
    for (const [id, ns] of hooked)
      sessions.push(build(hostId, toolId, 'hook', `${caller}\n${id}`, ns));
    rest.sort((a, b) => a.at.getTime() - b.at.getTime());
    let cur: Norm[] = [];
    const flush = () => {
      if (cur.length)
        sessions.push(
          build(
            hostId,
            toolId,
            'gap',
            `${caller}\n${cur[0]!.at.getTime()}`,
            cur,
          ),
        );
      cur = [];
    };
    for (const n of rest) {
      if (
        cur.length &&
        n.at.getTime() - cur[cur.length - 1]!.at.getTime() > SESSION_GAP_MS
      )
        flush();
      cur.push(n);
    }
    flush();
  }
  return sessions.sort((a, b) => (a.startedAt < b.startedAt ? 1 : -1));
}

/** What a public viewer gets. Nothing identifies a person, device, project or secret. */
export interface SharedSession {
  tool: string;
  source: 'hook' | 'gap';
  startedAt: string;
  durationSeconds: number;
  counts: Session['counts'];
  steps: {
    t: number;
    kind: StepKind;
    text: string;
    decision?: Step['decision'];
    outcome?: Step['outcome'];
    blocked?: boolean;
  }[];
}

// What a secret looks like, so a token typed where a program or host name should be never leaves.
const SECRET_PREFIX =
  /^(sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{16,}|github_pat_|glpat-|xox[abprs]-|AKIA[0-9A-Z]{12,}|AIza[0-9A-Za-z_-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.|npm_[A-Za-z0-9]{20,}|pypi-)/;
export function looksSecret(v: string): boolean {
  if (SECRET_PREFIX.test(v)) return true;
  return /^[A-Za-z0-9_+=-]{20,}$/.test(v) && /\d/.test(v) && /[A-Za-z]/.test(v);
}

function program(cmd: string): string {
  const words = cmd.trim().split(/\s+/);
  const w =
    words.find(
      (x) => !/^[A-Za-z_][A-Za-z0-9_]*=/.test(x) && x !== 'sudo' && x !== 'env',
    ) ?? '';
  const base = (w.replace(/\\/g, '/').split('/').pop() ?? '').replace(
    /\.(exe|cmd|bat)$/i,
    '',
  );
  return /^[A-Za-z0-9._+-]{1,40}$/.test(base) && !looksSecret(base) ? base : '';
}

/** The extension only, never the file name: short, letters first, not all digits. */
function ext(path: string): string {
  const m = /\.([A-Za-z][A-Za-z0-9]{0,5})$/.exec(
    path.replace(/\\/g, '/').split('/').pop() ?? '',
  );
  return m ? `.${m[1]!.toLowerCase()}` : '';
}

const INTERNAL_SUFFIX =
  /\.(internal|local|lan|corp|home|intranet|localdomain|test|invalid|localhost)$/;

/** A public website name only: two or more labels, no address, no internal domain. */
function hostName(u: string): string {
  try {
    const h = new URL(u).hostname.toLowerCase();
    if (!/^[a-z0-9.-]{3,100}$/.test(h)) return '';
    if (!h.includes('.') || h.startsWith('.') || h.endsWith('.')) return '';
    if (/^[0-9.]+$/.test(h)) return ''; // an IP address
    if (INTERNAL_SUFFIX.test(h)) return '';
    if (h.split('.').some((l) => !l || looksSecret(l))) return '';
    return h;
  } catch {
    return '';
  }
}

/** The MCP server name of `server/tool`, only for a real MCP call. */
function serverName(step: Step): string {
  if (step.action.toLowerCase() !== 'mcp') return '';
  const n = step.label.split('/')[0] ?? '';
  return /^[A-Za-z0-9._-]{1,60}$/.test(n) && !looksSecret(n) ? n : '';
}

/**
 * Redaction rules, fixed: a command shows its program only, a file shows its extension only, a
 * site shows its public host only, an MCP call shows the server name only, a secret shows its class
 * only. Times are seconds from the start. Device, folders, prompts and approver are never included.
 */
export function redactSession(s: Session, toolName: string): SharedSession {
  const t0 = Date.parse(s.startedAt);
  return {
    tool: toolName,
    source: s.source,
    startedAt: s.startedAt,
    durationSeconds: Math.round((Date.parse(s.endedAt) - t0) / 1000),
    counts: s.counts,
    steps: s.steps.map((x) => {
      let text = '';
      if (x.kind === 'command') text = program(x.label);
      else if (x.kind === 'file') text = ext(x.label);
      else if (x.kind === 'site') text = hostName(x.label);
      else if (x.kind === 'tool') text = serverName(x);
      else if (x.kind === 'secret')
        text = /^[a-z0-9-]{1,30}$/.test(x.action) ? x.action : 'secret';
      return {
        t: Math.max(0, Math.round((Date.parse(x.at) - t0) / 1000)),
        kind: x.kind,
        text,
        ...(x.decision ? { decision: x.decision } : {}),
        ...(x.outcome ? { outcome: x.outcome } : {}),
        ...(x.blocked ? { blocked: true } : {}),
      };
    }),
  };
}
