# AI security model (manar-api side)

Phase 10b (AI Advisory Pipeline Integration) scope: wiring manar-ai's
(Phase 10a, a separate repo) real gRPC `AnalysisService` into the real
authorization/tool-invocation pipeline. This is the `manar-api`-side half
of the AI security model — see `manar-ai`'s own `docs/ai-security-model.md`
for the advisory-only boundary, the fail-secure envelope contract, and the
deterministic+AI DLP hybrid design that this document builds on rather than
repeats.

## Non-negotiable invariant: AI can only add restriction, never remove it

Every mechanism below is a variation on one rule (Section 26, Section 80):
manar-ai's output can only ever push a decision toward _more_ restrictive
(higher risk score, a block, an audit flag), never toward _less_
restrictive. A `manar-ai` outage — unreachable, timed out, circuit open, or
internally failing over to its own fail-secure envelopes — must leave the
deterministic pipeline (Phases 5-8) behaving exactly as it did before Phase
10 existed. Concretely:

- `RiskEngine.finalRiskScore = max(deterministicRiskScore, aiAdvisoryScore ?? 0)`
  — AI can raise the final score, never lower it below the deterministic
  floor.
- DLP's before-call checkpoint only _blocks_; a `null`/absent advisory
  never blocks (the pre-Phase-10b behavior — no DLP check existed at all).
- DLP's after-call checkpoint only _redacts_; a `null`/absent advisory
  returns the tool's result unmodified (again, the pre-Phase-10b behavior).
- The prompt-injection `AgentRiskFlag` mechanism only _adds_ a fixed risk
  bump for a time-boxed window; it never grants anything, and the injected
  content itself is never trusted or executed by any code path regardless
  of whether a flag exists (Section 72 — the real security boundary is
  still deterministic task scope).

## `AiAdvisoryClient` (`src/ai-advisory/`)

The only place in this codebase that calls manar-ai's gRPC
`AnalysisService`. Wraps the vendored generated client
(`packages/manar-ai-client/`, copied from manar-ai's `clients/typescript/`
— see that package's `SOURCE_COMMIT` file for exactly which manar-ai commit
it was generated from, and manar-ai's `docs/grpc-typescript-client.md` for
why vendoring rather than a schema registry).

- **Timeout**: `AI_ADVISORY_TIMEOUT_MS`, default **2000ms**, applied as a
  gRPC deadline on every RPC. `RiskEngine.score` and
  `CredentialBrokerService.invoke` are both on hot, synchronous request
  paths (`POST /agent/v1/authorize`, `POST /agent/v1/tools/invoke`) — an
  unreachable or slow manar-ai must add small, bounded, predictable
  latency, never hang the pipeline.
- **Circuit breaker**: `AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD` (default 3)
  consecutive failures opens the circuit for
  `AI_ADVISORY_CIRCUIT_BREAKER_COOLDOWN_MS` (default 30s), during which
  every call returns `null` immediately with **no RPC attempted at all** —
  avoids paying the full timeout on every single request while manar-ai is
  known to be down. The next call after the cooldown is let through as a
  half-open trial; success closes the circuit, failure re-opens it.
- **Never throws**: every public method (`analyzeRisk`,
  `analyzePromptInjection`, `analyzeDlp`) returns `null`/absent on any
  failure — transport error, timeout, non-OK gRPC status, or circuit open.
  Callers must treat `null` as "no AI signal available," never propagate it
  as an error.
- **The confidence==0 convention**: manar-ai's own documented fail-secure
  marker for "the AI layer didn't actually run" is `confidence == 0.0` on
  `RiskAnalysisResult`/`PromptInjectionAnalysisResult` (see manar-ai's
  `docs/ai-security-model.md`, "Fail loudly, never fail open or fail
  silent"). `AiAdvisoryClient` collapses that to `null`, identically to a
  transport-level failure — a caller never has to special-case "the RPC
  succeeded but carried no real signal" versus "the RPC failed outright."
  `DlpAnalysisResult` has no single top-level confidence field (each
  finding carries its own, and the deterministic pattern-matching layer's
  findings are always real regardless of AI availability — manar-ai's
  Section 73) — `analyzeDlp` returns the result as-is on any successful
  RPC.

## `RiskEngine` combination rule (`src/risk/risk-engine.service.ts`)

`RiskEngine.score` calls `AiAdvisoryClient.analyzeRisk` with an
action-description string built from `{toolId, actionId, resource}` and a
context string carrying `taskId`/`riskCeiling`/delegation depth/the
deterministic score computed so far. The result:

```
deterministicRiskScore = clamp(baseline + delegation + tool-action + agent-risk-flag + policy-weight, 0, 100), then floored by policy.riskFloor
aiAdvisoryScore         = advisory?.score ?? null   (null if AiAdvisoryClient returned null)
finalRiskScore          = clamp(max(deterministicRiskScore, aiAdvisoryScore ?? 0), 0, 100)
```

`reasonCodes` keeps deterministic and AI-attributed contributors clearly
separate — every AI-derived entry is prefixed `ai_advisory_*`
(`ai_advisory_score:<n>`, `ai_advisory_recommended_action:<action>`,
`ai_advisory_signal:<signal>` per signal) — never blended into one
anonymous list, so an operator reading the response can always tell which
came from AI versus deterministic rules.

### `AgentRiskFlag` (prompt-injection follow-on risk)

A short-lived, deliberately minimal model (`agentId`, `reason`,
`expiresAt` — **not** the full `BehaviorBaseline`/`BehaviorObservation`
system, out of scope this phase). `RiskEngine.score` looks up whether the
requesting agent has an active, unexpired row via a single indexed DB
query (`@@index([agentId, expiresAt])`) — deliberately **not** another AI
call — and if one exists, adds a fixed `AGENT_RISK_FLAG_BUMP` (**20
points**) to `deterministicRiskScore` (part of the deterministic sum,
_before_ combining with `aiAdvisoryScore` — this bump is itself
deterministic, only the event that originally set the flag involved AI).
20 points is chosen to be large enough to visibly move a moderately-risky
action toward `REQUIRE_APPROVAL` on its own, without alone guaranteeing it
for every action.

## DLP checkpoints (`CredentialBrokerService.invoke`, `src/tools/`)

Two checkpoints, both wrapping the existing, unchanged
`CredentialBrokerService.invoke`/adapter-dispatch flow — neither forks or
duplicates it.

### Before-call: blocks on a severe finding

`AiAdvisoryClient.analyzeDlp({ content: JSON.stringify(params) })` runs
immediately after `Tool`/`ToolAction` resolution and the `enabled` check,
strictly before any credential resolution or adapter dispatch. **Blocking
threshold: `overallSeverity` is `SEVERITY_HIGH` or `SEVERITY_CRITICAL`** —
deliberately _above_ `SEVERITY_MEDIUM`. This threshold is not arbitrary: it
was chosen after observing manar-ai's own documented fail-secure behavior
(its `docs/ai-security-model.md`) escalates _any_ `DlpAnalysisResult` to at
least `SEVERITY_MEDIUM` whenever its own internal AI backend is
unavailable — a `source: "system"` marker finding, not a real detection.
Blocking on `MEDIUM` would mean manar-ai's own LLM-backend outage (a
separate concern from `AiAdvisoryClient`'s own reachability to manar-ai,
which fails to `null` and never blocks — see above) could block clean,
non-sensitive tool calls purely because its model backend was unreachable.
`HIGH`/`CRITICAL` are only ever reached by a genuine deterministic pattern
match (manar-ai's regex layer, always-on, independent of its own AI
backend) or a real, confident AI finding — never by the AI-unavailable
marker alone. Confirmed empirically against the real `manar-ai` container
configured exactly as `deploy/docker-compose.yml` ships it (unresolvable
AI backend): a genuine secret-shaped string (an AWS-access-key-shaped
value) scores `SEVERITY_HIGH`; ordinary non-sensitive params score
`SEVERITY_MEDIUM` (the AI-unavailable marker only) and are correctly not
blocked.

A block: records `dlp.blocked` via `AuditService.recordSafely` (finding
_types_/_source_/`redactedPreview` only — never the raw matched value,
identical to Phase 9a's credential-secrecy rule for tool credentials —
Section 73) and throws `DlpBlockedError`, mapped by `ToolInvokeController`
to `403 { decision: 'DENY', reason: 'dlp_policy_violation' }` — a generic
reason, never echoing the sensitive value or even the finding type back to
the caller. No `ToolInvocation` row is created (mirrors
`AuthorizationService`'s own DENY, not the "tool disabled" operational-
failure shape) and, structurally, no adapter/tool call is ever reached —
the block happens before credential resolution.

### After-call: redacts findings in the tool's own result

`AiAdvisoryClient.analyzeDlp({ content: JSON.stringify(result.data) })`
runs after a _successful_ tool call. Any _real_ finding (excluding
manar-ai's own `source: "system"` AI-unavailable status marker — see the
before-call section above for why that exclusion matters: without it,
manar-ai's own LLM-backend outage would redact every clean tool result,
not just genuinely sensitive ones — regardless of severity otherwise, since
this cannot undo an already-completed call, so the bar for "worth
redacting" is much lower than "worth blocking") causes `result.data` to be
replaced with a fixed placeholder
(`redactedToolResultPlaceholder` — `{ redacted: true, reason:
'sensitive_data_detected', findingCount, findingTypes }`) before it's
returned to the agent, and records `dlp.result_redacted` (same
redacted-metadata-only shape as the before-call block) via
`AuditService.recordSafely`.

**Why whole-value redaction, not substring splicing**: the gRPC contract
deliberately never transmits a finding's raw matched value _or_ its offset
within the scanned content, even internally within manar-ai (Section 73 —
`DlpFinding.redactedPreview` is a short, non-reversible preview only).
`manar-api` therefore cannot precisely excise just the matched
substring(s) from the original result without re-deriving detection
locally — which would duplicate manar-ai's ownership of DLP pattern
matching, exactly the "never re-implement detection in two places" problem
Section 73 already argues against for the LLM-only case. Given that real
interface constraint, replacing the entire flagged value is what actually
achieves the security goal (the agent's own context/output channel can
never become an exfiltration path for whatever the tool leaked) using only
the signal the contract legitimately provides.

## Prompt-injection advisory

After a _successful_ tool call, if `result.data` is a string,
`AiAdvisoryClient.analyzePromptInjection({ content: result.data, source:
'tool_output' })` runs against it directly. If `result.data` is instead a
structured object/array (e.g. a real SIEM `{ events: [...] }` response),
`collectStructuredInjectionText` (`src/tools/credential-broker.service.ts`,
added closing a real gap found while building Phase 13's demo) walks it —
depth capped at 5, concatenated string-leaf content capped at ~4KB, a
pure in-process scan that runs before the RPC call and adds no second
round-trip — and if it finds any string-valued leaves, the identical
single `analyzePromptInjection` call runs against that bounded,
concatenated text instead. Either way it's exactly one RPC call; a result
with nothing string-shaped at all (a bare number/boolean/`null`, or an
object with zero string leaves) skips the call entirely. Both paths run
against the **original**, pre-redaction text/structure (detection is
analysis-only and never itself returned to any caller, so there is no
leak risk in analyzing the unredacted value). On `detected === true`
(with `confidence > 0` — see the confidence==0 convention above):

1. Records `prompt_injection.detected` via `AuditService.recordSafely`
   (`confidence`/`indicators`/`explanation` — never the raw tool-output
   content itself).
2. Inserts an `AgentRiskFlag` row for the requesting agent, `reason:
"prompt_injection_detected:<toolId>/<actionId>"`,
   `expiresAt: now + 15 minutes` (`PROMPT_INJECTION_RISK_FLAG_TTL_MS`).

The injected content itself is never trusted, echoed, or executed by
anything in this codebase as a result of this mechanism — the actual
security boundary stays the deterministic task/grant scope
`AuthorizationService` already enforces (Section 72). This is a secondary,
defense-in-depth signal only: an agent whose tool output shows an
injection attempt becomes measurably higher-risk for what it tries _next_
(via `RiskEngine`'s `AgentRiskFlag` lookup), nothing more.

## Local infra (`deploy/docker-compose.yml`)

The `manar-ai` service builds from `../manar-ai` (a sibling checkout) and
runs `python -m app.grpc.server` (the real gRPC service — not the image's
default REST _debug_ interface). It is configured with `AI_PROVIDER=ollama`
and a deliberately DNS-unresolvable `OLLAMA_HOST`
(`http://ollama-not-configured.invalid:11434`, RFC 2606) — **not** because
a working local LLM is unavailable (this machine has one, via a
host-installed Ollama), but because a model capable of following this
service's structured-output contract takes multiple seconds per call on
typical local hardware, which is fundamentally incompatible with
`AiAdvisoryClient`'s sub-2-second budget on the hot authorization/
tool-invoke path — wiring a real LLM into this compose file would make its
behavior flaky and slow rather than more real. The unresolvable hostname
makes manar-ai's _own_ internal provider calls fail fast (immediate DNS
resolution failure, not a slow connect timeout), so this container's gRPC
layer, its deterministic DLP pattern-matching layer (unconditional, no LLM
dependency), and its documented fail-secure envelopes are all real and
exercised end-to-end against a genuine running service — only genuine
positive AI confidence output is unavailable from it, by design.

Test scenarios that need a _specific_, content-controlled AI signal (a
real high-confidence risk score pushing a decision to `REQUIRE_APPROVAL`;
a real prompt-injection detection) use `test/support/fake-analysis-service-server.ts`
instead — a real gRPC server implementing the identical generated
`AnalysisService` contract (`@manar-ai/grpc-client`, the same types
`AiAdvisoryClient` itself uses), with test-controlled canned responses.
This exercises the real wire protocol and real client code end-to-end;
only the response _content_ is a test double, standing in for genuine
model output the same way manar-ai's own `tests/grpc/test_analysis_service.py`
uses a `FakeProvider` to keep its gRPC-transport tests deterministic and
fast. See `test/ai-advisory.e2e-spec.ts` for exactly which scenarios use
the real `manar-ai` container versus this fake server, and why.

## Phase 12a follow-up: data residency enforcement (Section 54)

**Done**: this document's own architecture never checked `Tenant.allowExternalAi`
before this phase — a real, previously-open gap. `AiAdvisoryClient` now
consults it (`residencyAllows`, gated on `AI_ADVISORY_PROVIDER` actually
being external) before every RPC, reusing the exact same `null`
"no AI signal" fail-safe outcome this document already establishes for a
`manar-ai` outage — a residency block is just a different _reason_ for the
same outcome every existing caller already handles correctly. See
`docs/security.md`'s data residency section for the full mechanism and
`docs/threat-model.md`'s T10 for the threat this closes (and what it
deliberately still leaves open: `allowOutboundTelemetry`/`allowCloudStorage`
remain unenforced, since no telemetry-emitting or cloud-storage-writing
code path exists yet to enforce them against).
