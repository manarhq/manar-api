# Phase 15b: Incidents, Compliance & Integrations Pages — Design

Status: Approved (autonomous execution)
Scope: `manar-web` only
Depends on: Phase 15a (`GET /incidents`, `GET /compliance/frameworks`),
Phase 11b (`GET /tools` — reused for `/integrations`)

## Purpose

The last three Section 60 pages that were honest "not yet implemented"
stubs. After this phase, every route in the product's page list has
real content — either full functionality or, for the handful of pieces
genuinely deferred (AI-generated incident summaries, exhaustive
compliance coverage), an honest partial view rather than a stub.

## `/incidents` + `/incidents/[id]`

List (severity/status badges, filter by both), detail (description,
status-transition controls, linked audit events — use
`relatedCorrelationIds` to pull the actual audit trail via `GET /audit`,
giving a real "here's what happened" view, not just static text), a
create-incident form.

## `/compliance`

Framework-by-framework control list with status badges using exactly
the four values Section 55/Phase 15a define
(`MAPPED`/`EVIDENCE_AVAILABLE`/`PARTIALLY_IMPLEMENTED`/`NOT_EVALUATED`)
— **never render or imply "certified."** Show each control's evidence
description. This page's whole point is honesty about coverage; don't
let the UI's visual polish accidentally overstate what's mapped (e.g.
no green-checkmark-everywhere treatment that reads as "fully compliant"
if the underlying data says otherwise).

## `/integrations`

Reuse `GET /tools` (Phase 11b), reframed as an integrations view
(grouped by type/vendor, health/enabled status prominent) rather than a
raw registry table — this is deliberately the same data as `/tools`
through a different lens, not a new page's worth of new data. Confirm
this matches what Phase 15a's spec documents before building a
redundant fetch/model.

## Testing

- Real incidents created via the API appear in the list/detail, status
  transitions persist.
- Compliance page renders real seeded mapping data, never displays
  certification language.
- `/integrations` reflects the same live `Tool` data `/tools` does.
- RTL/i18n for all new pages, consistent with established conventions.
- As in prior UI phases, verify as much as the environment allows with
  real interaction (dev server + curl/DOM inspection or Playwright), and
  be explicit in the report about what was and wasn't actually verified.

## Out of scope this phase

- Nothing further planned after this — this closes the last stub pages
  from Section 60's list (AI-driven capabilities like incident
  auto-summarization remain Phase 10c, not yet built, and would slot
  into `/incidents/[id]` as an added feature later without restructuring
  this phase's work)
