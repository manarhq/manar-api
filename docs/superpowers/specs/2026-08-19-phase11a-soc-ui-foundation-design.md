# Phase 11a: SOC Console Foundation — Design

Status: Approved (autonomous execution)
Scope: `manar-api` (OpenAPI surface — a prerequisite this project never
had its own dedicated phase for, Section 8 required it from early on)
and `manar-web` (the actual foundation: auth flow, generated API client,
design system, i18n, layout shell)
Depends on: effectively all of Phases 1-10b (the API surface being
documented/consumed), but functionally only needs `manar-api` to expose
a real OpenAPI document — not every endpoint needs to be perfect,
just accurately reflect what exists today.

## Purpose

Ten phases of real backend exist (tenancy, human/agent auth, tasks/
delegation, policy/risk, tool gateway, approvals, audit chain, AI
advisory) with **zero UI**. This phase is the foundation everything in
Phase 11b+ builds on: nobody writes a page against hand-typed fetch
calls when a generated, typed client is possible (Section 8). Do not
build any specific SOC page's real functionality in this phase beyond
what's needed to prove the foundation works end-to-end (login → see
_something_ real from the API) — page-by-page functionality is Phase
11b+.

## Part 1 — `manar-api`: expose OpenAPI (Section 8, a gap to close now)

Add `@nestjs/swagger` (research current official NestJS OpenAPI docs),
decorate the existing controllers (`agents`, `tasks`, `policy`,
`approvals`, `evidence`, `audit`, tool-gateway's human-facing routes if
any — the mTLS agent-facing `/agent/v1/*` surface does NOT need to be in
this human-facing spec, it's a different consumer) with accurate
request/response DTOs reflecting what those endpoints actually accept/
return today (go read the real controllers/services — Phase 6-10b built
a lot, don't guess shapes). Expose `/api/v1/docs` (Swagger UI, dev-only
per Section 8 — gate behind `NODE_ENV`) and a raw OpenAPI JSON document
manar-web's codegen step will consume. This is real, accurate
documentation work, not a rubber stamp — if a DTO doesn't exist yet for
an endpoint (many probably don't, since these controllers were built
fast across many phases), add one that matches the actual runtime
behavior, don't invent aspirational shapes.

## Part 2 — `manar-web`: foundation

### Design system (Section 58)

Set up shadcn/ui as primitives, then build `components/manar/` —
Manar-specific components with a genuine SOC-console aesthetic (dark
mode first, dense, professional, no stock-shadcn-demo look, no
oversized rounded cards). Establish this now: typography scale, color
tokens (including a risk-score visual language — this recurs across
almost every future page), spacing/density conventions, a base
data-table component. **This is worth getting right once** rather than
drifting page by page — if the `frontend-design` or `artifact-design`
skill/guidance is available to you and gives useful direction on
avoiding a templated look, use it; otherwise use your own judgment
informed by what SOC/security-ops consoles (not generic SaaS dashboards)
actually look like.

### Bilingual architecture (Section 59)

Real i18n from the start — translation keys (not hardcoded strings),
LTR/RTL layout support verified in both directions (not just mirrored
text), locale-aware date formatting. Pick and integrate a current,
well-supported Next.js i18n library/App-Router pattern (research current
official Next.js internationalization guidance — routing conventions
have changed across versions). Seed with English + Arabic for whatever
UI text this foundation phase actually produces (login, shell nav,
error states) — later phases add their own page-specific strings using
the same convention.

### Auth flow (Section 67)

Standards-based Keycloak OIDC redirect login — do not collect passwords
in Manar's own forms. Since Phase 3 made tenant identity realm-per-
tenant (the Keycloak issuer URL encodes which tenant a user belongs to),
work out and document how a not-yet-authenticated user's browser session
gets routed to _their_ tenant's realm (there is no single shared login
page realm — this is a real architectural question this phase must
answer, not gloss over; a reasonable MVP answer is an initial
tenant-slug entry step before the OIDC redirect, but decide and document
your actual approach). Protect all app routes; handle token
storage/refresh per current recommended security guidance (research
this — token-in-JS-accessible-storage patterns have known pitfalls,
don't default to something insecure without checking current guidance).

### Generated API client + state

Generate a typed TypeScript client from `manar-api`'s new OpenAPI
document (research a current well-supported generator) as part of the
build/dev pipeline — never hand-type request/response shapes that
duplicate the backend's. Wire TanStack Query for server-state
caching/mutations (Section 57) using this generated client. Set up
Zustand for the lightweight cross-component UI state Section 57
describes (panel state, filters) — don't reach for it or Redux Toolkit
for anything TanStack Query already owns.

### Layout shell

Top-level app shell: sidebar nav (stub links to all Section 60 routes,
even ones with no real page yet — a route that 404s or shows "not yet
implemented" is honest; a nav link to nothing is confusing, so don't
add nav entries for pages that don't exist even as stubs), tenant/user
context display, dark-mode-first theming, responsive enough to be usable
at normal desktop widths (this is an operator console, not a marketing
site — don't over-invest in mobile).

### Proof-of-life page

`/overview` should show at least one genuinely live number from the real
API (e.g. active agent count via the generated client + TanStack Query)
— this is what proves the whole foundation (auth → typed client → real
data → rendered UI) actually works end to end, not just compiles.

## Testing

- Login redirect flow works against a real local Keycloak realm (reuse
  Phase 3's seeded tenant/user setup or create a minimal one for this
  test).
- An unauthenticated request to a protected route redirects to login;
  an authenticated one renders.
- RTL layout: render the shell with an Arabic locale active, assert
  direction-sensitive elements (nav, alignment) actually flip, not just
  that translated strings appear.
- `/overview`'s live number actually reflects real backend state (create
  an agent via the API, confirm the count updates).
- Generated client stays in sync: a CI/build step that regenerates the
  client from the live OpenAPI doc and fails if it drifts from what's
  committed (catches someone hand-editing generated files).

## Out of scope this phase

- Any specific page's full functionality beyond the proof-of-life
  overview number (Phase 11b+: agents, tasks, tools, policies,
  approvals, live feed, audit explorer, incidents, compliance,
  integrations, users/roles, settings)
- Full compliance/data-residency settings UI
- Topology visualization (Section 63, later)
