// k6 load test for manar-api: the agent decision path over mTLS with real
// enrolled agents, approvals, audit, the console's main reads and the
// governed MCP server. See load/README.md for setup and how to run.
//
//   PROFILE=smoke|steady|stress|soak   (default smoke)
//   API=http://127.0.0.1:3900  MTLS_PORT=3943
import http from 'k6/http';
import { check, fail } from 'k6';
import exec from 'k6/execution';

const PROFILE = __ENV.PROFILE || 'smoke';
const API = __ENV.API || 'http://127.0.0.1:3900';
const MTLS_PORT = __ENV.MTLS_PORT || '3943';
const KEYCLOAK = __ENV.KEYCLOAK || 'http://localhost:8081';
const DEMO_TENANT = 'vax-security-ops-demo';
const OUT = __ENV.OUT || 'results';

const AGENTS = JSON.parse(open('./.identities/agents.json'));
const CREDS = JSON.parse(open('./.identities/tenant-credentials.json'));
if (CREDS.tenantSlug === DEMO_TENANT) {
  throw new Error('Refusing to load-test the shared demo tenant');
}

// k6 presents only the first client certificate of tlsAuth on every
// connection (checked against /agent/v1/whoami), so run.sh starts one k6
// process per agent: SHARD picks this process's agent, SHARDS divides the
// rates. The server verifies every client certificate as usual.
const SHARD = Number(__ENV.SHARD || 0);
const SHARDS = Number(__ENV.SHARDS || 1);
const AGENT = AGENTS[SHARD % AGENTS.length];
const MTLS_BASE = `https://${__ENV.MTLS_HOST || '127.0.0.1'}:${MTLS_PORT}`;
const tlsAuth = [
  {
    cert: open(`./.identities/${AGENT.slug}.crt`),
    key: open(`./.identities/${AGENT.slug}.key`),
  },
];

// Requests per second per endpoint group at scale 1 (the pilot peak:
// 50 decisions/s across authorize, invoke and MCP tools/call).
const BASE = {
  authorize: 25,
  invoke: 15,
  mcp_call: 5,
  mcp_list: 3,
  approvals: 1, // one create + one decide per iteration
  audit: 2,
  console_pages: 5,
};

const PROFILES = {
  smoke: { stages: [{ target: 0.2, duration: '60s' }] },
  steady: {
    stages: [
      { target: 0.2, duration: '1m' }, // 10 decisions/s
      { target: 0.2, duration: '4m' },
      { target: 1, duration: '1m' }, // 50 decisions/s peak
      { target: 1, duration: '4m' },
      { target: 0.2, duration: '1m' },
      { target: 0.2, duration: '2m' },
    ],
  },
  // Doubles the load every 2 minutes up to 16x the pilot peak (800/s).
  stress: {
    stages: [1, 2, 4, 8, 12, 16].flatMap((x) => [
      { target: x, duration: '30s' },
      { target: x, duration: '90s' },
    ]),
  },
  soak: {
    stages: [
      { target: 0.5, duration: '2m' },
      { target: 0.5, duration: '58m' },
    ],
  },
};
const profile = PROFILES[PROFILE];
if (!profile) throw new Error(`Unknown PROFILE ${PROFILE}`);
const peak = Math.max(...profile.stages.map((s) => s.target));

// Rates are per 10 s so a shard can run a fraction of a request per second.
const perShard = (rps) => Math.max(1, Math.round((rps * 10) / SHARDS));

function scenario(group) {
  const rate = BASE[group];
  return {
    executor: 'ramping-arrival-rate',
    exec: group,
    startRate: perShard(rate * profile.stages[0].target),
    timeUnit: '10s',
    preAllocatedVUs: Math.ceil((rate * peak * 2) / SHARDS) + 2,
    maxVUs: Math.ceil((rate * peak * 20) / SHARDS) + 10,
    stages: profile.stages.map((s) => ({
      target: perShard(rate * s.target),
      duration: s.duration,
    })),
    tags: { group },
  };
}

// Proposed p95/p99 targets in ms (load/README.md), shared with aggregate.py.
// Thresholds also create the per-endpoint sub-metrics the summary reports.
const TARGETS = JSON.parse(open('./targets.json'));
const thresholds = {
  'checks{critical:yes}': ['rate>0.999'],
  checks: ['rate>0.99'],
};
for (const [ep, [p95, p99]] of Object.entries(TARGETS)) {
  thresholds[`http_req_duration{ep:${ep}}`] = [`p(95)<${p95}`, `p(99)<${p99}`];
  thresholds[`http_req_failed{ep:${ep}}`] = ['rate<0.01'];
}

export const options = {
  tlsAuth,
  // k6 cannot pin a private CA for the server; the client side skips
  // server verification, the server side (mTLS) is unchanged.
  insecureSkipTLSVerify: true,
  discardResponseBodies: false,
  // ONLY=authorize,invoke runs a subset (isolating one endpoint's cost).
  scenarios: Object.fromEntries(
    Object.keys(BASE)
      .filter((g) => !__ENV.ONLY || __ENV.ONLY.split(',').includes(g))
      .map((g) => [g, scenario(g)]),
  ),
  thresholds,
  summaryTrendStats: ['avg', 'med', 'p(90)', 'p(95)', 'p(99)', 'max', 'count'],
};

// ---- helpers ----

const tokens = {};
function bearer(role) {
  const now = Date.now();
  const cached = tokens[role];
  if (cached && cached.exp > now) return cached.value;
  const res = http.post(
    `${KEYCLOAK}/realms/${CREDS.keycloakRealm}/protocol/openid-connect/token`,
    {
      grant_type: 'password',
      client_id: CREDS.keycloakClientId,
      client_secret: CREDS.keycloakClientSecret,
      username: CREDS.users[role],
      password: CREDS.userPassword,
      scope: 'openid',
    },
    { tags: { ep: 'keycloak_token' } },
  );
  if (res.status !== 200) fail(`token for ${role}: HTTP ${res.status}`);
  const body = res.json();
  tokens[role] = {
    value: body.access_token,
    exp: now + (body.expires_in - 30) * 1000,
  };
  return body.access_token;
}

function pickAgent() {
  return { agent: AGENT, base: MTLS_BASE };
}

const JSON_HEADERS = { 'Content-Type': 'application/json' };

function agentPost(base, path, body, ep, extraHeaders = {}) {
  return http.post(`${base}${path}`, JSON.stringify(body), {
    headers: { ...JSON_HEADERS, ...extraHeaders },
    tags: { ep, name: ep },
  });
}

function humanGet(path, ep, role = 'TENANT_OWNER') {
  return http.get(`${API}${path}`, {
    headers: { Authorization: `Bearer ${bearer(role)}` },
    tags: { ep, name: ep },
  });
}

function decisionOf(res) {
  try {
    return res.json('decision');
  } catch {
    return undefined;
  }
}

// ---- scenarios ----

const INCIDENT = 'INC-2026-0042';
const HOST = 'WS-042';

export function authorize() {
  const { agent, base } = pickAgent();
  // 9 in 10 are in scope (ALLOW); 1 in 10 asks for an action the task
  // was never granted (DENY). Both are full decisions with a record.
  const inScope = exec.scenario.iterationInTest % 10 !== 0;
  const res = agentPost(
    base,
    '/agent/v1/authorize',
    inScope
      ? {
          taskId: agent.taskId,
          toolId: 'siem',
          actionId: 'search-events',
          resource: INCIDENT,
        }
      : {
          taskId: agent.taskId,
          toolId: 'iam',
          actionId: 'disable-user',
          resource: 'jdoe',
        },
    'authorize',
  );
  check(
    res,
    {
      'authorize: expected decision': (r) =>
        (r.status === 200 || r.status === 201) &&
        decisionOf(r) === (inScope ? 'ALLOW' : 'DENY'),
    },
    { critical: 'yes' },
  );
}

export function invoke() {
  const { agent, base } = pickAgent();
  const res = agentPost(
    base,
    '/agent/v1/tools/invoke',
    {
      taskId: agent.taskId,
      toolId: 'siem',
      actionId: 'fetch-incident',
      resource: INCIDENT,
      params: {},
    },
    'invoke_read',
  );
  check(
    res,
    { 'invoke: executed': (r) => r.status === 200 },
    { critical: 'yes' },
  );
}

const MCP_HEADERS = { Accept: 'application/json, text/event-stream' };

export function mcp_list() {
  const { agent, base } = pickAgent();
  const res = agentPost(
    base,
    `/agent/v1/tasks/${agent.taskId}/mcp`,
    { jsonrpc: '2.0', id: 1, method: 'tools/list' },
    'mcp_list',
    MCP_HEADERS,
  );
  check(res, {
    'mcp tools/list: tools returned': (r) =>
      r.status === 200 && (r.json('result.tools') || []).length > 0,
  });
}

export function mcp_call() {
  const { agent, base } = pickAgent();
  const res = agentPost(
    base,
    `/agent/v1/tasks/${agent.taskId}/mcp`,
    {
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: {
        name: 'siem__fetch-incident',
        arguments: { resource: INCIDENT, params: {} },
      },
    },
    'mcp_call',
    MCP_HEADERS,
  );
  check(
    res,
    {
      'mcp tools/call: executed': (r) =>
        r.status === 200 && r.json('result.isError') === false,
    },
    { critical: 'yes' },
  );
}

export function approvals() {
  const { agent, base } = pickAgent();
  const created = agentPost(
    base,
    '/agent/v1/tools/invoke',
    {
      taskId: agent.taskId,
      toolId: 'edr',
      actionId: 'isolate-host',
      resource: HOST,
      params: { nonce: `${exec.vu.idInTest}-${exec.scenario.iterationInTest}` },
    },
    'approval_create',
  );
  const ok = check(
    created,
    { 'approval: pending': (r) => r.status === 202 && !!r.json('approvalId') },
    { critical: 'yes' },
  );
  if (!ok) return;
  const res = http.post(
    `${API}/approvals/${created.json('approvalId')}/decide`,
    JSON.stringify({
      decision: exec.scenario.iterationInTest % 2 === 0 ? 'APPROVE' : 'DENY',
      reason: 'load test',
    }),
    {
      headers: {
        ...JSON_HEADERS,
        Authorization: `Bearer ${bearer('APPROVER')}`,
      },
      tags: { ep: 'approval_decide', name: 'approval_decide' },
    },
  );
  check(res, {
    'approval: decided': (r) => r.status === 200 || r.status === 201,
  });
}

export function audit() {
  if (exec.scenario.iterationInTest % 2 === 0) {
    const res = humanGet('/audit?limit=50', 'audit_list', 'AUDITOR');
    check(res, { 'audit list: 200': (r) => r.status === 200 });
  } else {
    const res = humanGet(
      '/audit?decision=DENY&toolId=iam&limit=50',
      'audit_search',
      'AUDITOR',
    );
    check(res, { 'audit search: 200': (r) => r.status === 200 });
  }
}

// The console overview and list pages (manar-web BFF upstream calls).
const CONSOLE_PATHS = [
  '/agents?limit=50',
  '/tasks?limit=50',
  '/approvals?status=PENDING&limit=50',
  '/tools',
  '/ai-systems',
  '/policies',
  '/incidents',
  '/kill-switches',
  '/users',
  '/tenant/settings',
];

export function console_pages() {
  const i = exec.scenario.iterationInTest;
  // The overview also verifies the audit chain; 1 in 25 page loads.
  if (i % 25 === 0) {
    const res = humanGet('/audit/verify', 'audit_verify');
    check(res, { 'audit verify: 200': (r) => r.status === 200 });
    return;
  }
  const res = humanGet(CONSOLE_PATHS[i % CONSOLE_PATHS.length], 'console');
  check(res, { 'console page: 200': (r) => r.status === 200 });
}

// ---- summary ----

export function handleSummary(data) {
  const rows = [];
  for (const ep of Object.keys(TARGETS)) {
    const d = data.metrics[`http_req_duration{ep:${ep}}`];
    const f = data.metrics[`http_req_failed{ep:${ep}}`];
    if (!d || !d.values.count) continue;
    const v = d.values;
    rows.push(
      `${ep.padEnd(16)} n=${String(v.count).padStart(7)}  p50=${v.med.toFixed(1).padStart(7)}  p95=${v['p(95)'].toFixed(1).padStart(7)}  p99=${v['p(99)'].toFixed(1).padStart(7)}  max=${v.max.toFixed(0).padStart(6)} ms  err=${(100 * (f ? f.values.rate : 0)).toFixed(2)}%`,
    );
  }
  const iters = data.metrics.iterations ? data.metrics.iterations.values : {};
  const dropped = data.metrics.dropped_iterations
    ? data.metrics.dropped_iterations.values.count
    : 0;
  const checks = data.metrics.checks ? data.metrics.checks.values : {};
  const text = [
    `profile=${PROFILE} shard=${SHARD}/${SHARDS} agent=${AGENT.slug} iterations=${iters.count} (${(iters.rate || 0).toFixed(1)}/s) dropped=${dropped} checks=${(100 * (checks.rate || 0)).toFixed(3)}%`,
    ...rows,
    '',
  ].join('\n');
  return {
    stdout: text,
    [`${OUT}/summary-${SHARD}.json`]: JSON.stringify(data, null, 1),
  };
}
