# Phase 10a: AI Service Foundation & Advisory Endpoints — Design

Status: Approved (autonomous execution)
Scope: `manar-ai` (Python/FastAPI, untouched since Phase 1's scaffold) —
fully independent of any other in-flight `manar-api` work, safe to
implement without coordination
Depends on: `manar-ai`'s Phase 1 scaffold only (provider abstraction,
config, logging, health endpoints, Docker, CI already exist there)
Followed by: Phase 10b (`manar-api` wires this service's gRPC contract
into `AuthorizationService` as an advisory signal — must run after this
phase produces a real, working `.proto` contract and server)

## Purpose

Sections 38-42: a vendor-neutral LLM provider abstraction, structured
(never free-text-parsed) AI outputs, and the specific advisory
capabilities the authorization pipeline needs — risk analysis,
prompt-injection detection, DLP/PII classification. **AI is advisory
only** (Section 26) — nothing built here can override a deterministic
decision; that constraint is enforced on the `manar-api` side in Phase
10b, but keep it in mind here too: every response type this service
returns must be a _signal_, never an "ALLOW"/"DENY" of its own.

## Layout

Populate `app/providers/`, `app/inference/`, `app/risk/`,
`app/prompt_security/`, `app/dlp/`, `app/grpc/` (currently empty
`__init__.py`-only placeholders from Phase 1) — leave `app/rag/`,
`app/policy/`, `app/incidents/`, `app/audit/`, `app/embeddings/`,
`app/behavior/`, `app/anomaly/`, `app/evaluation/` alone, they're Phase
10c.

## `LLMProvider` abstraction

```python
class LLMProvider(Protocol):
    async def complete_structured(self, prompt: str, schema: type[BaseModel]) -> BaseModel: ...
```

- `AnthropicProvider`: current official Anthropic Python SDK, Claude
  Sonnet 5, structured output via tool-use/schema enforcement (research
  current official guidance for getting reliably-structured output from
  Claude — don't hand-roll fragile prompt-based JSON parsing).
- `OllamaProvider`: current official Ollama Python client/API, structured
  output via its JSON-schema mode if available.
- `VLLMProvider`: OpenAI-compatible client pointed at a vLLM server's
  endpoint (vLLM's current official OpenAI-compatible server mode).
  **This deployment may have no GPU/model actually running** — implement
  the real client code and structured-output handling correctly, but if
  you can't stand up a live vLLM server in this environment, say so
  explicitly in your report and test this provider against a mocked HTTP
  layer instead (never silently skip testing it, and never claim it was
  verified against a live server if it wasn't).
- No domain code depends on any provider-specific message format —
  everything goes through `LLMProvider`. Provider selection is config-
  driven (typed `pydantic-settings`, per Phase 1's existing convention).
- Research and pick one current, well-supported, reasonably small
  open-weight model as the Ollama/vLLM default for local dev (document
  the choice, VRAM/latency tradeoffs, and license in
  `docs/dependency-decisions.md` per Section 41 — don't hardcode a
  specific model name without that justification).

## Structured output contracts (Pydantic — Section 42)

At minimum:

- `RiskAnalysisResult`: `score` (0-100), `confidence` (0-1), `signals`
  (list of strings), `explanation`, `recommendedAction`.
- `PromptInjectionAnalysisResult`: `detected` (bool), `confidence`,
  `indicators` (list), `explanation`.
- `DlpAnalysisResult`: `findings` (list of `{type, confidence,
redactedPreview}` — never the raw matched value itself, even
  internally in this response), `overallSeverity`.

Validate every provider response against these before returning — reject
malformed model output rather than passing it through (Section 42).
**AI failure (provider error, timeout, invalid output) must return a
clearly-failed/low-confidence result, never crash the caller and never
silently fabricate a "safe" default** — the caller (Phase 10b) is
responsible for treating that as "no advisory input," but this service's
job is to fail loudly and structurally, not to guess.

## Deterministic DLP layer (Section 73 — hybrid, not AI-only)

Before/alongside any AI DLP classification, run fast deterministic
pattern detection (API-key-shaped strings, private-key headers, JWT-
shaped tokens, email addresses, obvious credential patterns) — this must
work even if the LLM provider is completely unavailable, since "never
rely solely on an LLM to detect secrets" is an explicit requirement.
Combine deterministic + AI findings in `DlpAnalysisResult`; a
deterministic hit alone (no AI involved) must still surface a finding.

## gRPC service

Research the Model Context... no — research **gRPC**'s current official
Python (`grpcio`/`grpcio-tools` or the current recommended toolchain) and
TypeScript codegen setup, and `buf` (or current equivalent) for the
`.proto` toolchain, per Section 9. Define `.proto` contracts (owned by
`manar-ai`, per Section 9) for:

- `AnalyzeRisk(RiskAnalysisRequest) -> RiskAnalysisResult`
- `AnalyzePromptInjection(PromptInjectionRequest) -> PromptInjectionAnalysisResult`
- `AnalyzeDlp(DlpAnalysisRequest) -> DlpAnalysisResult`

Serve these over gRPC (Section 9 wants mTLS between `manar-api` and
`manar-ai` — for this phase, get the plain gRPC service working and
correctly tested first; if wiring real mTLS between the two services is
achievable in the time you have, do it using a self-signed/internal CA
convention consistent with Phase 4's OpenBao PKI approach, but do not
let mTLS setup block having a working, well-tested plaintext-internal-
network gRPC service — note clearly in your report which you achieved).
Also keep a REST/FastAPI debug interface per Section 9 ("REST may exist
as a development/debug interface").

Generate the TypeScript client bindings and commit them somewhere
`manar-api` can consume without manual type duplication (Section 9 — "a
reproducible mechanism for manar-api to consume the generated contract").
Since these are two separate repos, document exactly how (e.g. a
generated-client package published from `manar-ai`'s repo that
`manar-api` will vendor/copy in Phase 10b, or a script `manar-api` can
run against `manar-ai`'s checked-out `.proto` files) — pick something
reproducible and air-gap-compatible (no external schema registry, per
Section 9).

## Testing (pytest)

- Each provider's structured-output path against a mocked HTTP layer
  (Anthropic/Ollama/vLLM) — schema validation rejects malformed output.
- Deterministic DLP patterns catch known secret shapes even with the AI
  layer entirely disabled/unreachable.
- gRPC service: real client → real server (in-process or over a real
  socket) round trip for all three RPCs.
- A simulated provider failure (timeout/error) produces a structurally
  valid "failed/low-confidence" result, never an exception escaping to
  the gRPC layer as an unhandled 500 with no information.

## Docs

`docs/ai-security-model.md` (Section 87) — the advisory-only boundary,
provider abstraction, and the deterministic+AI DLP hybrid rationale.

## Out of scope this phase

- Wiring any of this into `manar-api`'s authorization pipeline (10b)
- RAG, embeddings, incident summarization, NL policy authoring, audit
  investigation, behavioral baselining/anomaly detection (10c)
- mTLS between the two services if genuinely not achievable in time
  (documented, not silently skipped)
