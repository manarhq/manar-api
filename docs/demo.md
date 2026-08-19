# Demo: VAX Security Operations

This is `manar-api`'s implementation of Phase 13 (Complete Demo):
`docs/superpowers/specs/2026-08-19-phase13-complete-demo-design.md`,
Section 85's seed data and Section 37's scripted scenario. It assembles
capabilities built across every prior phase — tenancy, human auth, agent
identity, task delegation/OpenFGA, policy/risk, tool gateway, approvals,
the audit chain, kill switches, and the AI advisory pipeline — into one
coherent, seeded, scripted, and automatically-tested demo. See
`docs/security.md` and `docs/authorization-model.md` for the underlying
mechanisms this walkthrough exercises; this document is the "how do I
actually run it" reference. It is deliberately UI-independent — everything
below works over the real HTTP/mTLS API and the real TypeScript SDK, no
`manar-web` involvement required.

## The scenario, in one paragraph

"SOC Response Agent" is scoped (by a real `Task` grant) to read SIEM
events/incidents and isolate one specific host (`WS-042`, isolation
gated behind human approval) — nothing else. It enrolls, searches SIEM
events for the seeded incident (`INC-2026-0042`), and — among the real
results — encounters a prompt-injection payload embedded in one event's
description, instructing it to disable an employee's account. It
"attempts" that (`iam.disable-user`) purely to demonstrate the point: the
attempt is denied immediately by deterministic task scope, regardless of
what the tool output said — the injected text was never trusted or
executed by anything in this codebase. It then isolates `WS-042` (via a
real human approval), the isolation is independently confirmed against
the real `demo-soc-tools` service, a kill switch is activated on the
agent (simulating an incident response action against the agent itself),
a previously-working action is immediately denied, the tenant's whole
audit hash chain is verified, and a signed evidence bundle is exported.

## Prerequisites

```bash
pnpm install
pnpm infra:up              # Postgres, Keycloak, OpenBao, OpenFGA, Temporal,
                            # Kafka, Redis, OpenSearch, demo-soc-tools, manar-ai
pnpm infra:openbao-init    # one-time PKI bootstrap (safe to re-run)
```

Then, in two separate terminals, leave the API and the Temporal worker
running for the rest of this walkthrough:

```bash
pnpm start:dev    # human-facing HTTP (port 3000) + agent-facing mTLS (port 3443)
pnpm worker:dev    # Temporal worker — required for the approval flow (Phase 8)
```

## 1. Seed the demo tenant

```bash
pnpm manar demo:seed
```

Idempotent — safe to re-run any time; it reuses whatever already exists
(by fixed slug/name, never by a random suffix) rather than duplicating it.
Provisions, via the real `TenantProvisioningService`/human-facing HTTP
API/`@manar/sdk-node` (never hand-inserted rows):

- **Tenant**: "VAX Security Operations Demo" (`vax-security-ops-demo`) —
  a real Keycloak realm and a real, isolated tenant database.
- **Four real Keycloak users**, all with password `Passw0rd!Demo2026`:

  | Username            | Role           |
  | ------------------- | -------------- |
  | `demo-owner`        | `TENANT_OWNER` |
  | `demo-soc-operator` | `SOC_OPERATOR` |
  | `demo-approver`     | `APPROVER`     |
  | `demo-auditor`      | `AUDITOR`      |

- **Three real enrolled agents** (real enrollment flow, real OpenBao-signed
  certificates): "SOC Response Agent," "Threat Hunting Agent," "Compromised
  Demo Agent."
- **`Tool`/`ToolAction` rows** for every SIEM/EDR/IAM/Firewall action,
  pointing at the real running `packages/demo-soc-tools` service.
- **Four real published policies**: "SOC Read Policy," "Endpoint Isolation
  Approval Policy," "IAM Restriction Policy," "No Secret Exfiltration
  Policy" (see `src/cli/commands/demo-seed.command.ts`'s own doc comment
  for exactly what each one's rule content says and why).
- **A task** granting "SOC Response Agent" exactly `siem.search-events`,
  `siem.fetch-incident`, `edr.get-host`, and `edr.isolate-host` (isolation
  itself still requires approval) — deliberately **not** any IAM/firewall
  action.

It also writes a gitignored handoff file, `.manar-demo/tenant-credentials.json`
(tenant id, Keycloak realm/client secret, agent ids, task id, demo user
list) — see `docs/demo.md`'s "Why a credentials file" note below for why
this exists.

## 2. Run the demo agent script

```bash
pnpm demo:agent
```

Runs `scripts/demo-agent.ts` — the real `@manar/sdk-node` `ManarAgent`
against your running `manar-api` and `demo-soc-tools`, playing every
persona in the narrative (the agent itself, plus the owner/approver/auditor
personas, via real Keycloak-issued JWTs) so the whole scenario is
demonstrable end to end from one process. Safe to re-run repeatedly.
Watch the console — every step is narrated and asserted; the script exits
non-zero at the first unexpected result rather than continuing past it.
It:

1. Mints a fresh enrollment token and enrolls "SOC Response Agent" live
   (a **second**, independent certificate from whatever `demo:seed`
   already issued it — re-enrolling an already-`ACTIVE` agent is legal;
   see that command's own doc comment).
2. Calls `siem.search-events`/`siem.fetch-incident` — real results from
   `demo-soc-tools`, including the seeded prompt-injection payload.
3. Attempts `iam.disable-user` — denied immediately (task scope).
4. Calls `edr.isolate-host` — `REQUIRE_APPROVAL`.
5. Decides `APPROVE` as the approver persona, polls, retries with the
   issued grant — executes, and independently re-confirms against
   `demo-soc-tools` directly that `WS-042` is actually isolated.
6. Activates a kill switch on the agent, retries a previously-working
   action (denied immediately), then deactivates it again (so the tenant
   stays usable for the next run).
7. Calls `GET /audit/verify` and `POST /evidence/export`, independently
   re-verifying the exported bundle's signature locally.

### Why a credentials file

`demo:seed`'s Keycloak client secret has no HTTP endpoint that returns it
— by design (Section 11: no application-level surface leaks a tenant's
Keycloak client credentials). `.manar-demo/tenant-credentials.json` is the
realistic equivalent of an operator handing a freshly provisioned
confidential client's secret to whichever tooling needs it next, the same
way a real deployment's provisioning step would. `scripts/demo-agent.ts`
then acts purely as an ordinary API/SDK client using credentials it was
given — it never touches Postgres or a Keycloak admin API directly.

### A known, documented limitation of a live run

Section 37 also expects "Phase 10b's prompt-injection advisory" to fire
when the agent encounters the injected SIEM content. Two things are worth
knowing if you watch this run and don't see a `prompt_injection.detected`
audit event:

1. **The real `manar-ai` container in local infra never produces a
   genuine positive detection.** `deploy/docker-compose.yml` deliberately
   configures it with an unresolvable AI backend (see
   docs/ai-security-model.md) — fast, real fail-secure envelopes, never a
   slow-but-real LLM call. Only `test/ai-advisory.e2e-spec.ts` and
   `test/complete-demo.e2e-spec.ts` exercise a genuine detection, via a
   real gRPC test double (`FakeAnalysisServiceServer`) standing in for
   `manar-ai`'s AI backend — not something a live `pnpm demo:agent` run
   against unmodified local infra can show.
2. **`CredentialBrokerService`'s prompt-injection hook only ever inspects
   a tool result whose `data` is a plain string** (`typeof result.data
=== 'string'`) — `demo-soc-tools`' real SIEM responses are structured
   JSON objects (`{ events: [...] }`), which that hook never inspects at
   all (a structured object result is DLP's concern, Section 73, not this
   one). This is a real, confirmed architectural boundary found while
   assembling this phase, not a bug introduced here — see
   `test/complete-demo.e2e-spec.ts`'s own doc comment for the full
   explanation and how that test proves the mechanism is genuinely real
   anyway (via one additional, string-returning tool call in the same
   tenant/task).

Neither limitation affects the deterministic parts of the scenario — the
`iam.disable-user` denial, the approval flow, the kill switch, the audit
chain, and evidence export are all fully real in every run, live or
automated.

## 3. Kill switches

Five scopes exist (`docs/kill-switches.md`); the demo script exercises the
`AGENT` scope on "SOC Response Agent." To drive any scope by hand, using
the owner token (`demo-owner`, obtained the same way `scripts/demo-agent.ts`
does — a Resource Owner Password Credentials grant against
`http://localhost:8081/realms/vax-security-ops-demo/protocol/openid-connect/token`):

```bash
# Activate/deactivate on the demo agent itself
curl -X POST http://localhost:3000/agents/<agentId>/kill-switch \
  -H "Authorization: Bearer $OWNER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"reason":"manual demo"}'
curl -X POST http://localhost:3000/agents/<agentId>/kill-switch/deactivate \
  -H "Authorization: Bearer $OWNER_TOKEN"

# Tenant-wide
curl -X POST http://localhost:3000/tenants/kill-switch \
  -H "Authorization: Bearer $OWNER_TOKEN" -H 'Content-Type: application/json' -d '{}'
curl -X POST http://localhost:3000/tenants/kill-switch/deactivate \
  -H "Authorization: Bearer $OWNER_TOKEN"
```

`POST /kill-switches/platform(/deactivate)` (the cross-tenant scope) also
requires `X-Platform-Operator-Token: $PLATFORM_KILL_SWITCH_OPERATOR_TOKEN`
— see `docs/kill-switches.md`. Not exercised by this demo (it would affect
every other tenant on this deployment, including any other one you might
have running).

## 4. Verify the audit chain

```bash
curl http://localhost:3000/audit/verify -H "Authorization: Bearer $AUDITOR_TOKEN"
# => {"valid":true}
```

Requires `AUDITOR`/`SECURITY_ADMIN`/`TENANT_OWNER` — use `demo-auditor`.
See `docs/audit-chain.md` for what this actually recomputes.

## 5. Export evidence

```bash
curl -X POST http://localhost:3000/evidence/export \
  -H "Authorization: Bearer $AUDITOR_TOKEN" -H 'Content-Type: application/json' \
  -d '{"taskId":"<taskId from demo:seed output or .manar-demo/tenant-credentials.json>"}'
```

Returns a real, signed JSON bundle — every matched `AuditEvent` with its
full hash-chain fields, plus surrounding context (agents, tasks, policy
versions, approvals, tool invocations), and an HS256 signature over
`sha256(canonicalize(bundle))`. See docs/audit-chain.md's "Evidence
export" section for the exact verification procedure
(`verifyEvidenceBundle`, `src/evidence/evidence-signing.util.ts`) — both
`scripts/demo-agent.ts` and `test/complete-demo.e2e-spec.ts` perform this
verification themselves, locally, rather than trusting the export
endpoint's own success response.

## The mandatory acceptance test

`test/complete-demo.e2e-spec.ts` automates this entire scenario and
asserts every checkpoint explicitly (not just "it didn't throw"):

```bash
pnpm test:e2e -- test/complete-demo.e2e-spec.ts
```

This is, per the project's own master prompt (Section 81/100), the single
most important test in the whole product — the executable proof of "done."
