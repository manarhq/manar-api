# Phase 11b: List/Search Endpoints & Core SOC Pages — Design

Status: Approved (autonomous execution)
Scope: `manar-api` (Part 1 — closing the list-endpoint gap Phase 11a
Part 2 discovered) and `manar-web` (Part 2 — building real page content
for the highest-priority operator surfaces)
Depends on: Phase 11a (generated client, design system, auth, layout
shell all exist). Part 1 should land and be merged before Part 2 starts,
same dependency shape as 11a's own two parts.

## Purpose

Phase 11a Part 2 discovered, while building the `/overview` proof-of-
life page, that **`manar-api` has no list/pagination endpoint for any
resource** — only single-item creates and gets. Section 66 (Audit UI),
and every other list-oriented SOC page (agents, tasks, tools, policies,
approvals), need this before any of them can be real. This phase closes
that gap and then builds the actual pages.

## Part 1 — `manar-api`: list endpoints

For each of `Agent`, `Task`, `Tool` (+`ToolAction`), `Policy` (+its
current published version), `ApprovalRequest`, `KillSwitch`,
`WebhookEndpoint` (if Phase 12a has landed by the time you do this —
check), add a paginated `GET` list endpoint per Section 8's pagination
requirements (cursor or offset — pick one convention and use it
consistently across all of them, document which and why). Support
reasonable filtering per resource (e.g. tasks by status/agent, approvals
by status, agents by status) — read Section 65/66's UI filter
requirements for what the frontend will actually need and make sure the
backend can serve it, don't build filters nobody asked for.

Add a **real audit search/list endpoint** (`GET /audit`) — Phase 9a/9b
built the tamper-evident chain, OpenSearch indexing, and evidence
export, but never a plain "browse/filter audit events" REST endpoint for
the UI's audit explorer (Section 66). This should query OpenSearch (the
derived, search-optimized copy, per Section 45) not Postgres directly,
with filters matching Section 66's list (time, agent, task, action,
tool, decision, risk range, correlation ID, event type).

**Fix the Keycloak client-secret workaround**: Phase 11a Part 2's BFF
currently uses standing Keycloak master-admin credentials configured
directly in `manar-web` to fetch the confidential client's secret at
login time — a real credential-hygiene smell (Section 99: minimize where
privileged credentials live). Add a proper `manar-api` endpoint (e.g.
`GET /tenants/:slug/oidc-config` or similar — human-facing, unauthenticated
since it's needed pre-login, but only exposing what's safe to expose:
issuer URL, client ID, and — if the confidential client's secret is
genuinely needed by the BFF flow you're using — have `manar-api` itself
hold the one standing Keycloak admin credential (it already talks to
Keycloak's Admin API for realm provisioning, Phase 3) and proxy just the
secret retrieval, rather than `manar-web` needing its own copy of
master-admin credentials at all). Update `manar-web`'s auth flow to use
this instead of its own Keycloak admin credentials, and remove those
credentials from `manar-web`'s config entirely.

## Part 2 — `manar-web`: core pages

Build real, functioning pages (using the new list endpoints + Phase
11a's generated client/design system/i18n) for, in priority order:

1. **`/agents` + `/agents/[id]`**: list (status, last seen), detail
   (identity/cert metadata, enrollment token generation UI — Section 34
   demo step — displays the raw token once, never again), revoke action.
2. **`/tasks` + `/tasks/[id]`**: list, detail (grants, delegation chain
   visualization if reasonably simple, status, revoke action), a create-
   task form (assign to an agent, set allowed tool/actions/resources,
   expiry, risk ceiling).
3. **`/approvals` + `/approvals/[id]`**: Section 65's approval card
   exactly — agent, task, requested action, tool, resource, params, risk
   score + explanation, policy, reason approval required, expiration,
   Approve/Deny buttons. **Race-safe/idempotent** (Section 65 explicit
   requirement — two rapid clicks or two tabs must not double-decide).
4. **`/live`**: the real SSE feed (Phase 11a already proved the
   mechanism on `/overview`) as an actual scrolling activity feed with
   basic filtering, matching Section 62's example event shapes.
5. **`/tools` + `/tools/[id]`**: registry browse, health/enabled status.
6. **`/policies` + `/policies/[id]`**: list, version history (immutable,
   per Phase 6), YAML/JSON view toggle, publish action, diff between
   versions.
7. **`/audit` + `/audit/[id]`**: Section 66's filter set against the new
   `GET /audit` endpoint, decision timeline view, evidence export button
   wired to Phase 9b's real export endpoint, chain-verify button wired
   to `GET /audit/verify`.

Every action button must call a real endpoint and reflect real resulting
state — no button that "looks like" it does something without a real
mutation behind it (Section 97's explicit prohibition).

## Testing

- Each new `manar-api` list endpoint: pagination works, filters work,
  tenant-scoped (never leaks another tenant's rows — reuse the existing
  tenant-isolation test pattern established since Phase 2).
- The audit search endpoint returns results consistent with what's
  actually in the chain (cross-check against a known seeded set of
  events).
- The new OIDC-config endpoint doesn't leak the actual client secret to
  the browser if you chose the proxy-the-secret-server-side design —
  verify this explicitly (inspect the real network response).
- `manar-web`: each page renders real data (create an agent/task/policy
  via the API, confirm it appears in the corresponding list without a
  page-specific mock). Approval double-click race test (Section 65) —
  fire two concurrent decide requests, confirm only one takes effect.
- Existing `manar-api` e2e suites and `manar-web`'s existing tests still
  pass unmodified.

## Out of scope this phase

- `/incidents`, `/compliance`, `/integrations`, `/users`, `/roles`,
  `/settings/*` real functionality — later UI phase(s), still honest
  stubs until then
- Topology visualization (Section 63)
- Full policy diff UI polish beyond a functional version comparison
