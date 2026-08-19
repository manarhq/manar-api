# Compliance mapping (Phase 15a, Section 55)

This is `manar-api`'s implementation of Section 55 of the master prompt:
`docs/superpowers/specs/2026-08-19-phase15a-classification-compliance-incidents-design.md`.

## This is mapping/evidence tracking, not certification

**`manar-api` is not certified against ISO/IEC 27001, NIST AI RMF, or any
other framework.** Nothing in this subsystem, its API responses, or its
UI may ever say otherwise. What this subsystem actually does: for a
representative (not exhaustive) subset of controls from two real,
current, publicly-published frameworks, it records an honest,
self-assessed status — `MAPPED`, `EVIDENCE_AVAILABLE`,
`PARTIALLY_IMPLEMENTED`, or `NOT_EVALUATED` — grounded in specific
capabilities this codebase has actually built and tested, each citing
the exact `docs/*.md` file and mechanism that provides the evidence. A
`NOT_EVALUATED`-equivalent gap is documented as a gap (see "Out of
scope" below), never silently omitted to look more complete than it is.

## Frameworks and sources consulted

Real, current, authoritative sources were consulted directly (WebFetch/
WebSearch against primary sources, not a summary blog post) before any
control was mapped:

- **ISO/IEC 27001:2022** — the current edition (superseding the 2013
  edition; 93 Annex A controls across four themes: Organizational,
  People, Physical, Technological). ISO does not publish the full
  standard text for free, so exact control **numbers and titles** were
  cross-checked against a registered-auditor reference source
  (<https://www.isms.online/iso-27001/annex-a-2022/>) rather than
  reconstructed from memory or training data — Annex A's control
  numbering/titles are consistently reproduced across every current
  ISO 27001 certification-body/consultancy reference because they are
  the standard's own published structure, not proprietary commentary.
- **NIST AI RMF 1.0** (`NIST.AI.100-1`, "Artificial Intelligence Risk
  Management Framework", published 2023-01-26) — the current version as
  of this phase; NIST's own site notes a revision is underway as part of
  a broader federal AI initiative, but 1.0 remains the current published
  framework. Confirmed directly against NIST's own site
  (<https://www.nist.gov/itl/ai-risk-management-framework>) and the
  NIST AI Resource Center's Core function/category/subcategory reference
  (<https://airc.nist.gov/AI_RMF_Knowledge_Base/AI_RMF/Core_And_Profiles/5-sec-core>)
  for exact subcategory identifiers (e.g. `GOVERN 6.1`) and their
  official text.
- **OWASP agentic AI security guidance** — not mapped this phase. At the
  time of this research pass there was no single stable, versioned OWASP
  publication analogous to ISO 27001 Annex A or the NIST AI RMF Core
  (OWASP's agentic-AI security work was still evolving multiple parallel
  drafts) to cite a stable control ID/title against without risking a
  citation to content that moves out from under this document. Documented
  here as a real, deliberate gap — see "Out of scope" below — rather than
  mapped against an unstable source.

## Methodology

1. For each framework, select a representative subset of controls
   covering the areas this product actually addresses: access control,
   audit logging, encryption, incident response, AI risk management, and
   credential management (per this phase's design spec — not exhaustive
   coverage of either standard, which would take far longer than one
   phase warrants).
2. For each selected control, read the relevant `docs/*.md` file(s) for
   real content (not paraphrased from memory) describing what this
   codebase has actually built and tested across its prior phases.
3. Assign exactly one of Section 55's four statuses, honestly:
   - **`MAPPED`** — a real, tested capability directly and substantially
     addresses this control.
   - **`EVIDENCE_AVAILABLE`** — a real capability provides meaningful
     evidence toward this control, but doesn't fully close it (e.g. data
     exists but no dedicated tooling is built on top of it yet).
   - **`PARTIALLY_IMPLEMENTED`** — a real, concrete start exists, but a
     material part of what the control asks for is genuinely missing
     (named explicitly in `evidenceDescription`, not glossed over).
   - **`NOT_EVALUATED`** — not assessed this phase (unused by the seed
     data below; every seeded control received a real assessment, but the
     status remains available for any control added by a future phase
     before it's been evaluated).
4. Write `evidenceDescription` as free text citing the specific
   `docs/*.md` file and mechanism — never a restatement of the control's
   own title, never fabricated.
5. Seed the result directly in this phase's own migration
   (`prisma/tenant/migrations/20260819060732_add_compliance_mapping/migration.sql`)
   — reference content describing the _product's_ own capabilities,
   identical for every tenant (not tenant-specific configuration), so
   every tenant (including ones provisioned in the future) gets it
   automatically via `TenantDatabaseManager.provisionTenant`'s `prisma
migrate deploy`, the same mechanism every other migration already uses.

## Data model

`ComplianceFramework` (`id`, `name`, `version`) →
`ComplianceControl` (`id`, `frameworkId`, `controlId` — the framework's
own numbering, e.g. `"A.5.15"` or `"GOVERN 6.1"`, `title`, `description`)
→ `ComplianceMapping` (`id`, `controlId` — unique, one mapping per
control, `status`, `evidenceDescription`, `evidenceReference` —
nullable, `assessedAt`). See `prisma/tenant.prisma` for the full schema
and `src/compliance/` for the read-only service/controller.

## Endpoints

Both JWT-guarded only (no role restriction — this is identical,
non-tenant-specific reference content about the product itself, not
sensitive per-tenant data; mirrors `GET /users`'s posture):

| Endpoint                                  | Purpose                                                                         |
| ----------------------------------------- | ------------------------------------------------------------------------------- |
| `GET /compliance/frameworks`              | List the frameworks mapped (`id`, `name`, `version`)                            |
| `GET /compliance/frameworks/:id/controls` | Every control for that framework, each with its current mapping status/evidence |

## Sample of the seeded mappings

The full set (18 controls: 12 ISO/IEC 27001:2022, 6 NIST AI RMF 1.0) is
in the migration referenced above. A representative sample:

| Framework          | Control    | Title                                           | Status                  | Evidence (abbreviated)                                                                                                                                       |
| ------------------ | ---------- | ----------------------------------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| ISO/IEC 27001:2022 | A.5.15     | Access control                                  | `MAPPED`                | OpenFGA task-scoped authorization + `PolicyEngine` restrictions — docs/authorization-model.md, docs/policy-model.md                                          |
| ISO/IEC 27001:2022 | A.8.15     | Logging                                         | `MAPPED`                | Tamper-evident, hash-chained `AuditEvent` log; `verifyAuditChain` — docs/audit-chain.md                                                                      |
| ISO/IEC 27001:2022 | A.8.16     | Monitoring activities                           | `EVIDENCE_AVAILABLE`    | OpenSearch indexing + live SSE feed exist; no dedicated alerting layer yet — docs/audit-chain.md                                                             |
| ISO/IEC 27001:2022 | A.8.2      | Privileged access rights                        | `PARTIALLY_IMPLEMENTED` | Role gating + privilege-escalation guard exist; no periodic access-review workflow — docs/authorization-model.md                                             |
| ISO/IEC 27001:2022 | A.5.28     | Collection of evidence                          | `MAPPED`                | Signed, independently hash-verifiable evidence export bundles — docs/audit-chain.md                                                                          |
| NIST AI RMF 1.0    | MAP 3.5    | Human oversight processes                       | `MAPPED`                | `REQUIRE_APPROVAL` human-in-the-loop gate; AI can only raise risk, never approve — docs/approvals.md, docs/policy-model.md                                   |
| NIST AI RMF 1.0    | GOVERN 6.1 | Third-party AI risk policies                    | `PARTIALLY_IMPLEMENTED` | `allowExternalAi` + Phase 15a's RESTRICTED-classification override are real technical controls, not a full vendor risk program — docs/data-classification.md |
| NIST AI RMF 1.0    | MANAGE 4.1 | Post-deployment AI monitoring/incident response | `PARTIALLY_IMPLEMENTED` | `Incident` model + audit/evidence-export/kill-switch machinery cover the primitives; no dedicated monitoring-plan artifact — docs/kill-switches.md           |

## `/integrations` needs no new backend

Confirmed and documented here per this phase's design spec: Section 60's
`/integrations` page is intentionally just an alternate view of the
existing `GET /tools` endpoint (Phase 11b), grouped/framed as
"integrations" rather than a raw registry table — every `Tool` row
already _is_ an integration, and (since this phase) every embedded
`ToolAction` row also carries its `classification` (see
`docs/data-classification.md`). No redundant `Integration` model was
built.

## Out of scope this phase

- **Exhaustive control coverage of either framework** — 12 of 93 ISO
  Annex A controls, 6 of the NIST AI RMF Core's subcategories. A
  deliberate, representative subset per the design spec, not an attempt
  at completeness.
- **SOC 2, ISO/IEC 42001, and EU AI Act mappings** — not built this
  phase. Documented here as a real, undone gap, not silently skipped.
- **OWASP agentic AI security guidance mapping** — no sufficiently
  stable, versioned publication to cite as of this phase's research pass
  (see "Frameworks and sources consulted" above).
- **Any write/update API for a mapping** — this is seeded reference data
  this phase, not a tenant-editable resource. A future re-assessment
  means a new migration, not a PATCH endpoint.
- **Certification of any kind.** Restated because it is the single most
  important constraint on this subsystem: nothing here is, or implies,
  an external audit outcome.
