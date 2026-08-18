# Phase 10c: RAG, Incident Summarization, Policy Assistant & Audit Investigation — Design

Status: Approved (autonomous execution) — **lower priority than Phases
11-13**; the core MVP acceptance scenario (master spec Section 2) does
not require these capabilities. Implement this phase opportunistically
once the higher-priority phases are underway or complete, not before.
Scope: `manar-ai` (RAG/embeddings/generation) + `manar-api` (endpoints,
permission-aware retrieval boundary)
Depends on: Phase 9b (OpenSearch is live, has audit events indexed),
Phase 10a/10b (provider abstraction, gRPC contract pattern, advisory
pipeline conventions)

## Purpose

Section 43's remaining capabilities (incident summarization, policy
recommendation/NL authoring, audit investigation) and Section 44's RAG,
using OpenSearch's vector capability per Section 45 (no second vector DB).

## RAG (`manar-ai`, `app/rag/` + `app/embeddings/`)

Local embeddings by default (Section 44) — research and pick a current
well-supported multilingual (Arabic + English) embedding model, document
VRAM/latency/license like Phase 10a did for the LLM. Index sources:
published `Policy` content and `AuditEvent`s (both already exist,
Phase 6/9a) via OpenSearch's vector fields (Phase 9b's index, or a
sibling one). **Permission-aware retrieval is not optional**: retrieval
must be scoped to the requesting tenant's own index namespace — an
agent or user must never retrieve a document they wouldn't otherwise be
authorized to see. Enforce this as a hard filter in the retrieval query
itself, not as a post-filter on results (a post-filter that still ran
the vector search across other tenants' data first is not the same
security property).

## New gRPC RPCs (extend Phase 10a's `AnalysisService` contract)

- `SummarizeIncident(context) -> IncidentSummaryResult` — takes a set of
  related audit events / free-text description (no formal `Incident`
  model exists yet in `manar-api`; don't invent tenant-DB persistence for
  it in this phase — operate on caller-supplied context, this becomes
  persisted once Phase 11's UI needs a real `Incident` entity).
- `SuggestPolicy(naturalLanguageDescription) -> PolicyDraftResult` —
  converts a description like "SOC agents may query SIEM events but
  endpoint isolation requires human approval" into a **draft** matching
  Phase 6's real rule content schema. **Never auto-published** — the
  `manar-api` side must create this as a `DRAFT` `PolicyVersion` only,
  requiring the normal human publish step, no exceptions.
- `InvestigateAudit(question, retrievedContext) -> AuditInvestigationResult` —
  answers "why was this denied?"-style questions using RAG-retrieved,
  permission-scoped audit events as context (the `manar-api` side does
  the permission-scoped retrieval and passes only already-authorized
  context in — this service never does its own unscoped lookup).

## `manar-api` endpoints (JWT-guarded)

- `POST /incidents/summarize` — gathers caller-specified `AuditEvent`s
  (must belong to the caller's tenant — reuse existing tenant-scoping
  patterns), calls the RPC, returns the structured summary.
- `POST /policies/suggest` — calls the RPC, persists the result as a new
  `DRAFT` `PolicyVersion` under a policy the caller names/creates, does
  **not** publish it.
- `POST /audit/investigate` — does the permission-scoped OpenSearch
  retrieval itself, passes only the caller's own tenant's matching
  events as context to the RPC, returns the answer.

## Testing

- Permission-aware retrieval: a query that would match another tenant's
  indexed content returns nothing from that tenant, even though the
  content is vector-similar (this is the one truly mandatory test in
  this phase — everything else is best-effort quality, this is a real
  security boundary).
- `SuggestPolicy` output, once accepted via `/policies/suggest`, is
  `DRAFT` and requires the normal `/policies/:id/versions/:versionId/publish`
  call to take effect — never auto-active.
- Incident summarization and audit investigation produce structurally
  valid results (Pydantic-validated, per Phase 10a's established
  pattern) and degrade the same fail-safe way Phase 10b established for
  provider/service failures — no crash, no fabricated answer presented
  as authoritative.

## Out of scope this phase

- Full `Incident` domain model/CRUD/UI (Phase 11, if pursued)
- Full `BehaviorBaseline`/`BehaviorObservation` modeling beyond Phase
  10b's lightweight `AgentRiskFlag` (may remain out of MVP scope
  entirely — note this as a known limitation in final documentation
  rather than building it under time pressure)
- Reranking (Section 44 explicitly: "if justified" — skip unless a
  concrete quality problem shows up in testing)
