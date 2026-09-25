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

## Optional: a real AI backend (`pnpm infra:up:ai`)

Plain `pnpm infra:up` points `manar-ai` at a deliberately unreachable
Ollama host, so every AI-advisory call gets manar-ai's own genuine
fail-secure envelope, never a real model response (see "A known,
documented limitation of a live run" below). To see a genuine model
response instead — e.g. for Phase 10c's `POST /incidents/summarize`
endpoint, backed by `AiAdvisoryClient`'s long-form lane
(`src/ai-advisory/ai-advisory-client.service.ts`) — bring up the optional
`ai` compose profile instead of plain `infra:up`:

```bash
pnpm infra:up:ai
```

This brings up the same stack as `pnpm infra:up`, plus a containerized
`ollama` service (`deploy/docker-compose.yml`), points `manar-ai` at it
via `MANAR_API_OLLAMA_HOST=http://ollama:11434` (overriding the
`.invalid` default), and pulls the two tags manar-ai uses: `qwen3:8b`
(chat/structured-output) and `qwen3-embedding:0.6b` (embeddings — always
Ollama-backed regardless of `AI_PROVIDER`, Section 44). Safe to re-run:
`ollama pull` is a no-op once a tag is already present (confirmed: a
second run completed in ~19s, entirely reconciliation, no re-download).

Deliberately namespaced as `MANAR_API_OLLAMA_HOST`/
`MANAR_API_OLLAMA_TIMEOUT_SECONDS`, not the bare `OLLAMA_HOST`/
`OLLAMA_TIMEOUT_SECONDS` names — this repo's compose substitution reads
whatever's in the invoking shell/`.env`, and both the native `ollama`
CLI _and_ manar-ai's own `.env.example` use the bare `OLLAMA_HOST` name.
If manar-api's compose substitution reused it, an operator who has
either of those set for unrelated reasons would silently leak that value
in and defeat the fail-secure default. Both vars are independently
overridable (`MANAR_API_OLLAMA_HOST=... pnpm infra:up:ai`) if you're
running Ollama somewhere other than the bundled container.

**First run**: the model pull is the slow part, not the container start.
On this machine, pulling both tags (~5.9GB total) over a fast connection
took under 2 minutes; a slower connection will take proportionally
longer (budget up to 20-30 minutes on typical home broadband). The
`manar-ollama-data` named volume held ~5.9GB after both pulls completed.

**CPU-only inference is slow — this is expected, not a bug.** This
host's Docker daemon has no GPU passthrough configured (`docker run
--gpus all ...` fails with "no known GPU vendor found" — see the
`ollama` service's own doc comment in `deploy/docker-compose.yml`), so
the containerized Ollama runs `qwen3:8b` on CPU. Measured on this
machine: a trivial two-word reply took ~13s once the model was already
warm in memory; a full `SummarizeIncident` call (real structured-output
generation, called directly against manar-ai's actual gRPC service, not
just raw Ollama) took **~127s**. Both numbers are well past
`AI_ADVISORY_LONGFORM_TIMEOUT_MS`'s 30s default (`.env.example`) — on
CPU-only hardware like this, a live longform call will still come back
as `available: false` (fail-secure, not broken) unless you raise that
budget. Before a live demo of a longform endpoint, set a more generous
value in your own `.env` (or shell environment before `pnpm start:dev`):

```bash
AI_ADVISORY_LONGFORM_TIMEOUT_MS=180000   # 3 minutes — generous for CPU-only qwen3:8b
```

Hardware with GPU passthrough into Docker (not configured here) would be
dramatically faster and likely need no override at all. The **hot lane**
(`AnalyzeRisk`/`AnalyzePromptInjection`/`AnalyzeDlp`, `AI_ADVISORY_TIMEOUT_MS`'s
2s budget) is a different story — see the note below, it stays
fail-secure against a real backend on hardware like this regardless.

**Warm the model before a live demo**: the first inference against a
freshly pulled model pays a one-time cold-load cost on top of normal
generation latency. Warm it once, shortly before the live portion of a
demo (Ollama unloads an idle model from memory after a few minutes, so
don't warm hours ahead):

```bash
docker exec manar-ollama ollama run qwen3:8b "hi"
```

**If you skip this step** (or run plain `pnpm infra:up`), everything
else in this walkthrough still works exactly as documented — none of
the deterministic parts of the scenario (task scope denial, approvals,
kill switches, the audit chain, evidence export) ever depended on a real
AI backend. You'll just continue to see manar-ai's fail-secure envelopes
in place of genuine model output.

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
- **Five real published policies**: "SOC Read Policy," "Endpoint Isolation
  Approval Policy," "Restricted Classification Approval Policy" (Phase
  15a — see docs/data-classification.md), "IAM Restriction Policy," "No
  Secret Exfiltration Policy" (see `src/cli/commands/demo-seed.command.ts`'s
  own doc comment for exactly what each one's rule content says and why).
- **A task** granting "SOC Response Agent" exactly `siem.search-events`,
  `siem.fetch-incident`, `edr.get-host`, and `edr.isolate-host` (isolation
  itself still requires approval) — deliberately **not** any IAM/firewall
  action.

It also writes a gitignored handoff file, `.manar-demo/tenant-credentials.json`
(tenant id, Keycloak realm/client secret, agent ids, task id, demo user
list) — see `docs/demo.md`'s "Why a credentials file" note below for why
this exists.

### Optional: the Microsoft connector against the DEMO FIXTURE

```bash
docker compose -f deploy/docker-compose.yml up -d --build demo-soc-tools  # image with /microsoft
pnpm manar tenants:migrate                                               # adds ToolProtocol MICROSOFT
pnpm manar demo:seed --microsoft-fixture-url http://localhost:3101
```

This additionally registers `microsoft-graph` and `microsoft-defender`
(ADR-0004) pointed at the local mimic of the Entra token endpoint, Graph
and Defender served by demo-soc-tools under `/microsoft`, stores the
fixture's app secret in OpenBao, publishes "Microsoft Connector Approval
Policy" (every Microsoft mutation needs approval, reads are allowed) and
creates a task (`microsoftTaskId` in the credentials file) letting the SOC
Response Agent read fixture incident `4201`, investigate its user and
device, and, after approval, disable the user, revoke sessions and
isolate the device.

Say it out loud in the demo: **this is a DEMO FIXTURE, not Microsoft and not
a customer tenant.** Every object it returns carries
`"_dataOrigin": "DEMO_FIXTURE"`, and the tool descriptions say so. Its state
is at `GET http://localhost:3101/microsoft/_fixture/state` and resets with
`POST /microsoft/_fixture/reset`. The automated proof is
`test/microsoft-connector.e2e-spec.ts`.

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

1. **Even with a genuine local AI backend up (`pnpm infra:up:ai` — see
   "Optional: a real AI backend" above), a live `pnpm demo:agent` run
   still won't show a genuine positive detection here.** Two independent
   reasons, not one:
   - Plain `pnpm infra:up` (no profile) still points `manar-ai` at a
     deliberately unresolvable AI backend by default (see
     docs/ai-security-model.md) — fast, real fail-secure envelopes,
     never an LLM call, unless you opt into `pnpm infra:up:ai`.
   - Even opted in, `AnalyzePromptInjection` (what this scenario
     actually exercises) is a **hot-lane** call —
     `AI_ADVISORY_TIMEOUT_MS`'s 2s budget
     (`src/ai-advisory/ai-advisory-client.service.ts`). Real qwen3:8b
     inference on hardware without GPU passthrough into Docker took
     ~13s for a trivial reply in testing — nowhere close to 2s — so the
     hot lane still returns manar-ai's fail-secure envelope against a
     real backend on hardware like this, by the same design tradeoff
     `AI_ADVISORY_TIMEOUT_MS`'s own doc comment describes (Section 80:
     an AI outage/slowness must add no more than a short, bounded
     amount of latency to the hot authorization path, never block it).
     Only `test/ai-advisory.e2e-spec.ts` and `test/complete-demo.e2e-spec.ts`
     exercise a genuine detection, via a real gRPC test double
     (`FakeAnalysisServiceServer`) standing in for `manar-ai`'s AI backend.
     What `pnpm infra:up:ai` _does_ make observable live is the
     **long-form** lane instead (`POST /incidents/summarize` and friends —
     see "Optional: a real AI backend" above), which isn't part of this
     scenario's own narrative.
2. **`CredentialBrokerService`'s prompt-injection hook now also inspects
   structured (object/array) tool results, not only a plain string.**
   Before this fix, the hook only ran `AnalyzePromptInjection` when a tool
   result's `data` was a plain string — `demo-soc-tools`' real SIEM
   responses are structured JSON objects (`{ events: [...] }`), which used
   to be entirely invisible to this hook (a real, confirmed architectural
   boundary found while assembling Phase 13, not a bug introduced there).
   That gap is closed: the hook now walks a structured result with a
   bounded traversal (depth capped at 5, concatenated string-leaf content
   capped at ~4KB — see `collectStructuredInjectionText` in
   `src/tools/credential-broker.service.ts`), and if it finds any
   string-valued leaves, passes the bounded, concatenated text to the
   same single `AnalyzePromptInjection` call the plain-string path already
   made — never a second RPC call, never one call per event/leaf. The
   traversal itself adds no RPC of its own and the per-call
   `AI_ADVISORY_TIMEOUT_MS` deadline described in limitation 1 above is
   unchanged — but a structured-result invocation now reaches that
   `AnalyzePromptInjection` call at all (it used to be skipped outright),
   so it now makes 3 sequential hot-lane RPC calls per invocation instead
   of 2, matching what a string-result invocation already made.
   **This makes structured results inspectable — it does not, by itself,
   make a live run against real local inference complete within the hot
   lane's 2s budget.** Limitation 1 above is unaffected by this fix and
   still applies exactly as described: even with `pnpm infra:up:ai` and
   this bounded-traversal fix both in place, a live `pnpm demo:agent` run
   will most likely still show manar-ai's fail-secure envelope for
   `AnalyzePromptInjection` on CPU-only hardware, because real inference
   latency (~13s measured minimum) still blows past `AI_ADVISORY_TIMEOUT_MS`
   long before this traversal (a fast, in-process, pre-RPC step) becomes
   relevant. `test/complete-demo.e2e-spec.ts`'s own doc comment has the
   full explanation of the pre-fix boundary and how the test proves the
   mechanism is genuinely real via `FakeAnalysisServiceServer`.

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
