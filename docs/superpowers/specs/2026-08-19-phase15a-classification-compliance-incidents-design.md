# Phase 15a: Data Classification, Compliance Mapping & Incidents — Design

Status: Approved (autonomous execution)
Scope: `manar-api` only
Depends on: Phase 6 (`PolicyEngine`), Phase 12a (`AiAdvisoryClient`
residency check), Phase 9a (`AuditService`)

## Purpose

The last three genuinely-unbuilt Section 53/55/70 items: data
classification as a policy input, an honest (never fabricated)
compliance-control mapping subsystem, and a first-class `Incident`
model. These close the backend gaps blocking `manar-web`'s remaining
`/compliance` and `/incidents` pages (`/integrations` does NOT need new
backend — see below).

## Data classification (Section 53)

Add `classification` (enum `PUBLIC | INTERNAL | CONFIDENTIAL |
RESTRICTED`, default `INTERNAL` — not `PUBLIC`, the safer default) to
`ToolAction`. Thread it through as:

- A new optional match condition in `PolicyEngine`'s rule schema
  (Phase 6) — `resourceClassification` — so a policy CAN express "deny/
  require-approval for RESTRICTED-classified actions," but nothing is
  hardcoded to auto-deny; that's what policies are for. Seed one real
  example policy demonstrating this (can extend Phase 13's demo
  policies or be a new one — your call).
- A new input to `RiskEngine`'s deterministic scoring (higher
  classification → higher baseline risk contribution, documented).
- **A real enforcement point**, per Section 53's own example ("RESTRICTED
  data cannot be sent to external cloud AI provider"): extend Phase
  12a's `AiAdvisoryClient` residency check — it currently only looks at
  the tenant's `allowExternalAi` flag; add a second, independent check
  that skips any call to an external provider when the specific tool
  action being analyzed is classified `RESTRICTED`, regardless of the
  tenant-level flag (a RESTRICTED action is RESTRICTED even for a tenant
  that otherwise permits external AI). Same fail-safe "no AI signal"
  path as every other reason this client already skips a call — don't
  invent a new response shape.

Migration.

## Compliance mapping (Section 55 — accuracy is the whole point)

**Before writing any mapping, research the actual current official
publications** (WebFetch/WebSearch) for whichever frameworks you map —
at minimum ISO/IEC 27001 (current edition) and NIST AI RMF (current
version); OWASP's agentic AI security guidance if a stable current
reference exists. Do not fabricate control IDs or descriptions from
memory. For each control you map, the `ImplementationStatus` must
reflect an honest self-assessment of what this codebase has _actually
built and tested_ across all fourteen-plus prior phases — read the
relevant `docs/*.md` files to ground each claim, don't guess. Use only
the four statuses Section 55 specifies: `MAPPED | EVIDENCE_AVAILABLE |
PARTIALLY_IMPLEMENTED | NOT_EVALUATED`. **Never claim certification.**
The UI/API must never say "Manar is ISO 27001 certified" — only mapping/
evidence-status language.

Data model: `ComplianceFramework` (`id`, `name`, `version`),
`ComplianceControl` (`id`, `frameworkId`, `controlId` — the framework's
own numbering, `title`, `description`), `ComplianceMapping` (`id`,
`controlId`, `status`, `evidenceDescription` — free text pointing at
real capabilities, e.g. "Task-scoped OpenFGA authorization with
deterministic subset-checked delegation, see docs/authorization-model.md
and docs/task-delegation.md," `evidenceReference` — nullable link/path,
`assessedAt`).

Seed real mappings for a reasonably representative subset of controls
from each framework (not exhaustive coverage of either standard — that
would take far longer than this phase warrants; a genuine, honestly-
assessed subset covering the areas this product actually addresses:
access control, audit logging, encryption, incident response, AI risk
management, credential management — is the right scope).

Endpoints (JWT-guarded): `GET /compliance/frameworks`, `GET
/compliance/frameworks/:id/controls` (each with its current mapping
status/evidence).

## Incidents (Section 70)

`Incident`: `id`, `title`, `description`, `severity` (enum `LOW | MEDIUM
| HIGH | CRITICAL`), `status` (enum `OPEN | INVESTIGATING | RESOLVED |
CLOSED`), `relatedCorrelationIds` (Json array — links to audit events/
tool invocations sharing a correlation ID, the connective tissue this
product already has via Phase 9a rather than inventing a new relation
model), `createdBy` (FK `UserProfile`), `createdAt`, `resolvedAt`
(nullable).

Endpoints (JWT-guarded): `POST /incidents`, `GET /incidents` (Phase
11b's cursor pagination, filter by status/severity), `GET /incidents/:id`,
`PATCH /incidents/:id` (status transitions, resolution notes). Audit
every create/status-change via `AuditService.recordSafely()`.

No AI-generated incident summarization in this phase (that's Phase
10c, not yet built) — this is plain CRUD + linkage to existing audit
data.

## `/integrations` — no new backend needed

Confirm and document (in this phase's own doc, see below) that Section
60's `/integrations` page is intentionally just an alternate view of the
existing `GET /tools` endpoint (Phase 11b) grouped/framed as
"integrations" rather than a raw registry table — every `Tool` row
already IS an integration. Do not build a redundant `Integration` model.

## Testing

- Classification-based policy rule: a seeded policy denies/requires-
  approval for a RESTRICTED action, verified via the real authorize
  pipeline.
- RESTRICTED classification blocks external AI advisory calls even when
  `allowExternalAi = true` — assert zero RPC attempts at the transport
  level, mirroring Phase 12a's existing residency test pattern.
- Compliance endpoints return the real seeded mappings; assert the API
  response never contains certification language.
- Incident CRUD, status transitions, tenant isolation, audit trail for
  create/status-change.
- Existing e2e suites across all prior phases still pass unmodified.

## Docs

`docs/compliance-mapping.md` — the frameworks/versions consulted (with
sources), the honest-assessment methodology, and an explicit statement
that this is mapping/evidence tracking, not certification.
`docs/data-classification.md` — the enum, its policy/risk/AI-residency
enforcement points.

## Out of scope this phase

- AI-generated incident summarization (Phase 10c)
- Exhaustive control coverage of either compliance framework
- SOC 2 / ISO 42001 / EU AI Act mappings (documented as not yet done,
  not fabricated to look complete)
