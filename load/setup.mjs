// Prepares the load-test tenant: N enrolled agents, one task each, and the
// PEM files k6 needs for mTLS. Run after `demo:seed` for the load tenant
// (see load/README.md). Never point it at the shared demo tenant.
//
//   node load/setup.mjs            # 10 agents
//   LOAD_AGENTS=30 node load/setup.mjs
//
// Writes load/.identities/ (gitignored): <slug>.crt/.key and agents.json.
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { ManarAgent } from '../packages/sdk-node/dist/index.js';

const API = process.env.LOAD_API ?? 'http://localhost:3900';
const KEYCLOAK = process.env.KEYCLOAK_BASE_URL ?? 'http://localhost:8081';
const CREDS =
  process.env.LOAD_CREDENTIALS ?? '.manar-demo/tenant-credentials.json';
const COUNT = Number(process.env.LOAD_AGENTS ?? 10);
const OUT = 'load/.identities';
const DEMO_TENANT = 'vax-security-ops-demo';

const creds = JSON.parse(readFileSync(CREDS, 'utf8'));
if (creds.tenantSlug === DEMO_TENANT) {
  throw new Error('Refusing to load-test the shared demo tenant');
}

async function token(username) {
  const res = await fetch(
    `${KEYCLOAK}/realms/${creds.keycloakRealm}/protocol/openid-connect/token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'password',
        client_id: creds.keycloakClientId,
        client_secret: creds.keycloakClientSecret,
        username,
        password: creds.userPassword,
        scope: 'openid',
      }),
    },
  );
  if (!res.ok) throw new Error(`token for ${username}: HTTP ${res.status}`);
  return (await res.json()).access_token;
}

async function api(method, path, bearer, body) {
  const res = await fetch(`${API}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${bearer}`,
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${path}: HTTP ${res.status} ${text}`);
  return text ? JSON.parse(text) : undefined;
}

/** Keeps the identity in memory; this script writes the PEMs itself. */
class MemoryStore {
  identity = null;
  async save(identity) {
    this.identity = identity;
  }
  async load() {
    return this.identity;
  }
  async clear() {
    this.identity = null;
  }
}

mkdirSync(OUT, { recursive: true, mode: 0o700 });
const owner = await token(creds.users.TENANT_OWNER);
const existing = (await api('GET', '/agents?limit=200', owner)).items ?? [];
const agents = [];

for (let i = 1; i <= COUNT; i++) {
  const slug = `load-agent-${String(i).padStart(2, '0')}`;
  let agent = existing.find((a) => a.slug === slug);
  agent ??= await api('POST', '/agents', owner, {
    slug,
    displayName: `Load Agent ${i}`,
  });

  if (!existsSync(`${OUT}/${slug}.key`)) {
    const { token: enrollToken } = await api(
      'POST',
      `/agents/${agent.id}/enrollment-tokens`,
      owner,
    );
    const store = new MemoryStore();
    await new ManarAgent({ endpoint: API, identityStore: store }).enroll(
      enrollToken,
    );
    writeFileSync(`${OUT}/${slug}.crt`, store.identity.certificatePem, {
      mode: 0o600,
    });
    writeFileSync(`${OUT}/${slug}.key`, store.identity.privateKeyPem, {
      mode: 0o600,
    });
  }

  // One task per agent, like a real deployment: decisions for different
  // agents never contend on one task row's execution counter.
  const task = await api('POST', '/tasks', owner, {
    name: `Load task ${slug} ${new Date().toISOString()}`,
    description: 'Load test: SIEM read plus EDR isolation behind approval.',
    assignedAgentId: agent.id,
    allowedToolActions: [
      { toolId: 'siem', actionId: 'search-events' },
      { toolId: 'siem', actionId: 'fetch-incident' },
      { toolId: 'edr', actionId: 'get-host' },
      { toolId: 'edr', actionId: 'isolate-host' },
    ],
    allowedResourceSelectors: [
      { toolId: 'siem', pattern: '*' },
      { toolId: 'edr', pattern: 'WS-042' },
    ],
    forbiddenActions: [],
    expiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString(),
    riskCeiling: 50,
  });
  agents.push({ slug, agentId: agent.id, taskId: task.id });
  console.log(`${slug}: task ${task.id}`);
}

writeFileSync(`${OUT}/agents.json`, JSON.stringify(agents, null, 2), {
  mode: 0o600,
});
copyFileSync(CREDS, `${OUT}/tenant-credentials.json`);
console.log(`Wrote ${agents.length} agents to ${OUT}/agents.json`);
