/**
 * Phase 13 (Complete Demo, Section 37) — the scripted SOC agent
 * walkthrough, using the real `@manar/sdk-node` `ManarAgent` against a
 * real, already-running `manar-api` (`pnpm start:dev` + `pnpm worker:dev`)
 * and a real, already-running `packages/demo-soc-tools` (`pnpm infra:up`).
 * Run `pnpm manar demo:seed` first — see docs/demo.md for the full,
 * exact command sequence.
 *
 * This script plays every persona in the narrative (the agent itself, via
 * the SDK; the tenant owner, approver, and auditor, via real
 * Keycloak-issued JWTs obtained through the Resource Owner Password
 * Credentials grant) so the whole scenario is demonstrable end to end
 * from one process, exactly the way `test/complete-demo.e2e-spec.ts`
 * automates and asserts it. Every step below fails loudly (non-zero exit,
 * clear message) rather than continuing past an unexpected result — this
 * scenario is meant to be watched, not silently degraded.
 *
 * What it proves, step by step:
 *   1. Enroll "SOC Response Agent" — real enrollment token, real
 *      certificate, private key never leaves this process.
 *   2. SIEM search-events / fetch-incident on INC-2026-0042 -> ALLOW,
 *      real results from the real demo-soc-tools service — including a
 *      seeded event containing a prompt-injection payload.
 *   3. The script's own logic "falls for" that payload and attempts
 *      iam.disable-user in response -> DENIED, by deterministic task
 *      scope, regardless of what the tool output said (Section 72) — the
 *      injected text was never trusted or executed by anything here.
 *   4. edr.isolate-host on WS-042 -> REQUIRE_APPROVAL.
 *   5. A human (the "approver" persona) decides APPROVE via the real
 *      POST /approvals/:id/decide.
 *   6. The agent polls, retries with the issued grant -> EXECUTE — and
 *      the script independently re-verifies against demo-soc-tools
 *      directly (never trusting the gateway's own response alone) that
 *      WS-042 is now actually isolated.
 *   7. A kill switch is activated on the agent -> a previously-working
 *      action is denied immediately, no grace period.
 *   8. GET /audit/verify -> the tenant's whole hash chain is valid.
 *   9. POST /evidence/export -> a real, independently-signature-verified
 *      evidence bundle for this scenario.
 */
import { readFileSync } from 'node:fs';
import { FileIdentityStore, ManarAgent } from '@manar/sdk-node';
import type { InvokeToolResult } from '@manar/sdk-node';
import { verifyEvidenceBundle } from '../src/evidence/evidence-signing.util';

const API_ENDPOINT =
  process.env.MANAR_DEMO_API_ENDPOINT ?? 'http://localhost:3000';
const MTLS_ENDPOINT =
  process.env.MANAR_DEMO_MTLS_ENDPOINT ?? 'https://127.0.0.1:3443';
const KEYCLOAK_BASE_URL =
  process.env.KEYCLOAK_BASE_URL ?? 'http://localhost:8081';
const DEMO_TOOLS_BASE_URL =
  process.env.DEMO_SOC_TOOLS_BASE_URL ?? 'http://localhost:3101';
const DEMO_TOOLS_API_KEY =
  process.env.DEMO_TOOLS_API_KEY ?? 'manar-dev-demo-tools-key';
const EVIDENCE_SIGNING_SECRET =
  process.env.APPROVAL_GRANT_SIGNING_SECRET ??
  'dev-only-approval-grant-signing-secret-change-me';
const CREDENTIALS_FILE_PATH =
  process.env.MANAR_DEMO_CREDENTIALS_FILE ??
  '.manar-demo/tenant-credentials.json';

const DEMO_HOST_ID = 'WS-042';
const DEMO_INCIDENT_ID = 'INC-2026-0042';

interface DemoTenantCredentials {
  tenantId: string;
  tenantSlug: string;
  keycloakRealm: string;
  keycloakClientId: string;
  keycloakClientSecret: string;
  userPassword: string;
  users: Record<string, string>;
  agents: Record<string, { id: string; slug: string }>;
  taskId: string;
}

function section(title: string): void {
  console.log(`\n${'='.repeat(70)}\n${title}\n${'='.repeat(70)}`);
}

function assert(condition: boolean, message: string): asserts condition {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

/** Narrows `InvokeToolResult` to its `EXECUTED` variant (`{success, data?, errorMessage?}`) or throws with the full actual result for debugging. */
function assertExecuted(
  result: InvokeToolResult,
  context: string,
): asserts result is Extract<InvokeToolResult, { status: 'EXECUTED' }> {
  if (result.status !== 'EXECUTED') {
    throw new Error(
      `${context}: expected status EXECUTED, got ${JSON.stringify(result)}`,
    );
  }
}

/** Narrows `InvokeToolResult` to its `PENDING` variant (`{reason, riskScore, approvalId}`) or throws with the full actual result for debugging. */
function assertPending(
  result: InvokeToolResult,
  context: string,
): asserts result is Extract<InvokeToolResult, { status: 'PENDING' }> {
  if (result.status !== 'PENDING') {
    throw new Error(
      `${context}: expected status PENDING, got ${JSON.stringify(result)}`,
    );
  }
}

/** Narrows `InvokeToolResult` to its `DENIED` variant (`{reason}`) or throws with the full actual result for debugging. */
function assertDenied(
  result: InvokeToolResult,
  context: string,
): asserts result is Extract<InvokeToolResult, { status: 'DENIED' }> {
  if (result.status !== 'DENIED') {
    throw new Error(
      `${context}: expected status DENIED, got ${JSON.stringify(result)}`,
    );
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function requireUser(users: Record<string, string>, role: string): string {
  const username = users[role];
  if (!username) {
    throw new Error(
      `Credentials file has no "${role}" user — re-run "pnpm manar demo:seed"`,
    );
  }
  return username;
}

async function getUserToken(input: {
  realm: string;
  clientId: string;
  clientSecret: string;
  username: string;
  password: string;
}): Promise<string> {
  const response = await fetch(
    `${KEYCLOAK_BASE_URL}/realms/${encodeURIComponent(input.realm)}/protocol/openid-connect/token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'password',
        client_id: input.clientId,
        client_secret: input.clientSecret,
        username: input.username,
        password: input.password,
        scope: 'openid',
      }),
    },
  );
  if (!response.ok) {
    throw new Error(
      `Failed to obtain a token for "${input.username}": HTTP ${response.status}`,
    );
  }
  const body = (await response.json()) as { access_token: string };
  return body.access_token;
}

async function httpJson<T>(
  method: 'GET' | 'POST',
  path: string,
  token: string,
  body?: unknown,
): Promise<T> {
  const response = await fetch(new URL(path, API_ENDPOINT), {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(
      `${method} ${path} failed: HTTP ${response.status}${text ? `: ${text}` : ''}`,
    );
  }
  return (await response.json()) as T;
}

async function getRealDemoHost(
  hostId: string,
): Promise<{ id: string; isolated: boolean }> {
  const response = await fetch(
    `${DEMO_TOOLS_BASE_URL}/v1/edr/hosts/${hostId}`,
    {
      headers: { Authorization: `Bearer ${DEMO_TOOLS_API_KEY}` },
    },
  );
  if (!response.ok) {
    throw new Error(
      `GET /v1/edr/hosts/${hostId} against the real demo-soc-tools service failed (HTTP ${response.status})`,
    );
  }
  return (await response.json()) as { id: string; isolated: boolean };
}

async function main(): Promise<void> {
  section('Loading demo tenant credentials');
  let credentials: DemoTenantCredentials;
  try {
    credentials = JSON.parse(
      readFileSync(CREDENTIALS_FILE_PATH, 'utf8'),
    ) as DemoTenantCredentials;
  } catch (error) {
    throw new Error(
      `Could not read "${CREDENTIALS_FILE_PATH}" — run "pnpm manar demo:seed" first (see docs/demo.md). Original error: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const socResponseAgent = credentials.agents['soc-response-agent'];
  if (!socResponseAgent) {
    throw new Error(
      'No "soc-response-agent" entry in the credentials file — re-run "pnpm manar demo:seed"',
    );
  }
  console.log(`Tenant: ${credentials.tenantSlug} (${credentials.tenantId})`);
  console.log(`Task: ${credentials.taskId}`);
  console.log(`Agent: ${socResponseAgent.slug} (${socResponseAgent.id})`);

  section('Authenticating human personas (real Keycloak, real JWTs)');
  const ownerToken = await getUserToken({
    realm: credentials.keycloakRealm,
    clientId: credentials.keycloakClientId,
    clientSecret: credentials.keycloakClientSecret,
    username: requireUser(credentials.users, 'TENANT_OWNER'),
    password: credentials.userPassword,
  });
  const approverToken = await getUserToken({
    realm: credentials.keycloakRealm,
    clientId: credentials.keycloakClientId,
    clientSecret: credentials.keycloakClientSecret,
    username: requireUser(credentials.users, 'APPROVER'),
    password: credentials.userPassword,
  });
  const auditorToken = await getUserToken({
    realm: credentials.keycloakRealm,
    clientId: credentials.keycloakClientId,
    clientSecret: credentials.keycloakClientSecret,
    username: requireUser(credentials.users, 'AUDITOR'),
    password: credentials.userPassword,
  });
  console.log('Owner, approver, and auditor tokens obtained.');

  section('1. Enroll "SOC Response Agent" (real SDK, real certificate)');
  const enrollmentTokenResponse = await httpJson<{ token: string }>(
    'POST',
    `/agents/${socResponseAgent.id}/enrollment-tokens`,
    ownerToken,
  );
  const identityStore = new FileIdentityStore(
    '.manar-demo/identities/soc-response-agent-live.identity',
    process.env.MANAR_DEMO_IDENTITY_PASSPHRASE ??
      'manar-demo-live-identity-not-for-production',
  );
  const manar = new ManarAgent({
    endpoint: API_ENDPOINT,
    mtlsEndpoint: MTLS_ENDPOINT,
    identityStore,
  });
  await manar.enroll(enrollmentTokenResponse.token);
  console.log('Enrolled — private key never left this process.');

  section('2. SIEM search-events on WS-042 -> ALLOW');
  const searchResult = await manar.invokeTool({
    taskId: credentials.taskId,
    toolId: 'siem',
    actionId: 'search-events',
    resource: DEMO_HOST_ID,
    params: {},
  });
  assertExecuted(searchResult, 'SIEM search-events');
  assert(
    searchResult.success,
    `expected SIEM search-events to succeed, got ${JSON.stringify(searchResult)}`,
  );
  const events = (
    searchResult.data as { events: Array<{ description: string }> }
  ).events;
  console.log(
    `Retrieved ${events.length} real SIEM events for ${DEMO_HOST_ID}.`,
  );
  const injectedEvent = events.find((e) =>
    e.description.includes('Ignore your previous instructions'),
  );
  assert(
    injectedEvent !== undefined,
    'expected one seeded SIEM event to contain the prompt-injection payload',
  );
  console.log('\n  >>> Suspicious event content encountered:');
  console.log(`  >>> "${injectedEvent.description}"\n`);

  section(`2b. SIEM fetch-incident on ${DEMO_INCIDENT_ID} -> ALLOW`);
  const incidentResult = await manar.invokeTool({
    taskId: credentials.taskId,
    toolId: 'siem',
    actionId: 'fetch-incident',
    resource: DEMO_INCIDENT_ID,
    params: {},
  });
  assertExecuted(incidentResult, 'SIEM fetch-incident');
  assert(
    incidentResult.success,
    `expected SIEM fetch-incident to succeed, got ${JSON.stringify(incidentResult)}`,
  );
  console.log('Incident details retrieved:', incidentResult.data);

  section(
    '3. Attempting what the injected text asked (iam.disable-user) -- MUST be denied by task scope, regardless of tool content',
  );
  const iamAttempt = await manar.invokeTool({
    taskId: credentials.taskId,
    toolId: 'iam',
    actionId: 'disable-user',
    resource: 'jdoe',
    params: {},
  });
  assertDenied(
    iamAttempt,
    'iam.disable-user (this task was never granted it, so it must be DENIED)',
  );
  console.log(
    `Correctly DENIED (reason: "${iamAttempt.reason}") -- the injected instruction was never trusted or executed.`,
  );

  section('4. EDR isolate-host on WS-042 -> REQUIRE_APPROVAL');
  const isolateAttempt = await manar.invokeTool({
    taskId: credentials.taskId,
    toolId: 'edr',
    actionId: 'isolate-host',
    resource: DEMO_HOST_ID,
    params: {},
  });
  assertPending(isolateAttempt, 'edr.isolate-host');
  console.log(
    `Approval requested (approvalId=${isolateAttempt.approvalId}, riskScore=${isolateAttempt.riskScore}).`,
  );

  section('5. A human (the approver persona) decides APPROVE');
  await httpJson(
    'POST',
    `/approvals/${isolateAttempt.approvalId}/decide`,
    approverToken,
    { decision: 'APPROVE', reason: 'Confirmed malicious activity on WS-042' },
  );
  console.log('Decision submitted.');

  section('Polling for the issued grant');
  let grantToken: string | undefined;
  const deadline = Date.now() + 30_000;
  for (;;) {
    const polled = await manar.getApproval(isolateAttempt.approvalId);
    if (polled.status === 'APPROVED') {
      grantToken = polled.grantToken;
      break;
    }
    if (polled.status === 'DENIED' || polled.status === 'EXPIRED') {
      throw new Error(`Approval ended up ${polled.status}, expected APPROVED`);
    }
    if (Date.now() > deadline) {
      throw new Error('Timed out waiting for the approval to resolve');
    }
    await sleep(250);
  }
  assert(grantToken !== undefined, 'expected a grant token once APPROVED');
  console.log('Grant token obtained.');

  section('Retrying edr.isolate-host with the grant -> EXECUTE');
  const isolateExecuted = await manar.invokeTool({
    taskId: credentials.taskId,
    toolId: 'edr',
    actionId: 'isolate-host',
    resource: DEMO_HOST_ID,
    params: {},
    grantToken,
  });
  assertExecuted(isolateExecuted, 'grant-backed edr.isolate-host retry');
  assert(
    isolateExecuted.success,
    `expected the grant-backed retry to succeed, got ${JSON.stringify(isolateExecuted)}`,
  );
  console.log('Executed. Gateway response:', isolateExecuted.data);

  section(
    '6. Independently confirming isolation against demo-soc-tools directly',
  );
  const realHost = await getRealDemoHost(DEMO_HOST_ID);
  assert(
    realHost.isolated,
    `expected the real demo-soc-tools service to show ${DEMO_HOST_ID} isolated, got ${JSON.stringify(realHost)}`,
  );
  console.log(
    `Confirmed: ${DEMO_HOST_ID} is actually isolated (verified directly, not just via the gateway's own response).`,
  );

  section('7. Activating a kill switch on "SOC Response Agent"');
  await httpJson(
    'POST',
    `/agents/${socResponseAgent.id}/kill-switch`,
    ownerToken,
    {
      reason:
        'Phase 13 demo: simulating an incident response on the agent itself',
    },
  );
  console.log('Kill switch active.');

  section('Retrying a previously-working action -> must be DENIED immediately');
  const deniedByKillSwitch = await manar.invokeTool({
    taskId: credentials.taskId,
    toolId: 'siem',
    actionId: 'search-events',
    resource: DEMO_HOST_ID,
    params: {},
  });
  assertDenied(
    deniedByKillSwitch,
    'previously-working SIEM search-events, once the kill switch is active',
  );
  console.log(`Correctly DENIED (reason: "${deniedByKillSwitch.reason}").`);

  section('Deactivating the kill switch (cleanup, so re-runs stay usable)');
  await httpJson(
    'POST',
    `/agents/${socResponseAgent.id}/kill-switch/deactivate`,
    ownerToken,
  );
  console.log('Kill switch deactivated.');

  section('8. GET /audit/verify (auditor persona)');
  const verifyResult = await httpJson<{ valid: boolean; brokenAt?: string }>(
    'GET',
    '/audit/verify',
    auditorToken,
  );
  assert(
    verifyResult.valid,
    `expected the audit chain to verify as valid, got ${JSON.stringify(verifyResult)}`,
  );
  console.log('Audit chain verified: valid.');

  section('9. POST /evidence/export (auditor persona)');
  const exportResult = await httpJson<{
    exportId: string;
    bundle: unknown;
    signature: { signature: string };
  }>('POST', '/evidence/export', auditorToken, {
    taskId: credentials.taskId,
  });
  const verified = await verifyEvidenceBundle(
    exportResult.bundle,
    exportResult.signature.signature,
    EVIDENCE_SIGNING_SECRET,
  );
  assert(
    verified.valid,
    `expected the exported evidence bundle's signature to verify, got ${JSON.stringify(verified)}`,
  );
  console.log(
    `Evidence bundle exported (exportId=${exportResult.exportId}) and its signature independently verified: valid.`,
  );

  section('Demo complete — every checkpoint passed.');
}

main().catch((error: unknown) => {
  console.error('\nDemo agent script FAILED:');
  console.error(
    error instanceof Error ? (error.stack ?? error.message) : error,
  );
  process.exitCode = 1;
});
