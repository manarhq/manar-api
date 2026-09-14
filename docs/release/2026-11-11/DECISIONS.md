# Release 2026-11-11 — engineering decisions

Decisions taken under the brief's "make routine engineering decisions
independently, explain consequential tradeoffs" mandate. Each records what
was decided, what it rules out, and what would change it. Larger
architectural substitutions get a full ADR in `adr/`; nothing so far has
needed one, because no foundational technology has been replaced.

---

## D1 — Cut the release branch from local `main` without merging

`manar-api`'s local `main` was ahead 1 / behind 1 of `origin/main`. The
"behind" commit is `8f641bf`, the GitLab MR merge for
`fix/mvp-ai-unblock`; every commit it merges was already present locally,
and local `main` carried one additional doc-correction commit. Local
content is therefore a strict superset of `origin/main` content.

**Decided:** branch from local `main` and leave the divergence alone.
Merging or pushing is outside what this brief authorises (§2), and
reconciling a merge-commit-only divergence adds risk for no content gain.
`manar-web` was 2 behind with a clean tree and was fast-forwarded first —
a local-only operation.

**Consequence:** the release branch's history will need one reconciliation
with `origin/main` before any MR. That is a deliberate deferral, recorded
here so it is not a surprise.

---

## D2 — Runtime coverage is derived per read, never stored

Brief §3.1 requires that a manually registered AI system is not
automatically treated as covered by runtime enforcement, and that coverage
be shown as governed / observed-only / declared-only / monitoring
unavailable.

**Decided:** no `coverage` column on `AiSystem`. The value is computed on
every read from real `ToolInvocation` rows and `Agent.status`
(`src/ai-systems/ai-system-coverage.ts`), and the supporting counts travel
with the verdict so the console can explain it without a second request.

**Why:** a stored value is correct on the day it is written and quietly
wrong afterwards. The entire reason to show coverage is to stop the console
claiming assurance the platform cannot demonstrate; a stale column would
reintroduce exactly that.

**Ruled out:** a nightly job that materialises coverage. It would be
cheaper to query and would let the list endpoint filter on coverage, but it
reintroduces staleness for a value whose only purpose is honesty.

**Consequence, accepted:** `GET /ai-systems` deliberately has **no
coverage filter**. Filtering server-side would require deriving coverage
for every row in the tenant, or silently filtering only the current page —
and the second would make the returned counts untrustworthy, which is the
failure this whole decision exists to avoid. Revisit if a tenant's
inventory grows past the point where client-side coverage filtering on a
loaded page is useful.

**Separately:** `MONITORING_UNAVAILABLE` is an explicit input
(`telemetryAvailable: false`), never inferred from an empty result. The
observation query is wrapped so a failure degrades to that value rather
than failing the whole read — an operator who can see the record marked
"monitoring unavailable" is better off than one who gets a 500, and the
brief requires silence and "we could not look" to be distinguishable.

---

## D3 — Lifecycle transitions are a server-enforced edge table; separation of duties applies to exactly one edge

**Decided:** `lifecycleState` cannot be changed by `PATCH`. It moves only
through `POST /ai-systems/:id/transitions`, checked against
`ALLOWED_TRANSITIONS`. `DRAFT → ACTIVE` is not an edge — activating
without review is the control this state machine exists to impose.
`RETIRED` is terminal.

**Separation of duties applies only to `REVIEW → ACTIVE`,** and is checked
against the actor of the most recent `DRAFT → REVIEW` transition (not the
record's creator, because a record can be reworked and resubmitted).

**Why not apply it to every edge:** an operator suspending a system they
activated is a legitimate, urgent action. Requiring a second person there
creates pressure to skip the governance record entirely during an
incident — which costs more evidence than it protects.

**Known gap, deliberately not blocking:** if a system reached `REVIEW`
with no recorded submission transition (pre-existing data, or a data fix),
the check has nothing to compare against and does not block. It logs a
warning rather than silently passing. Making it block would fail
legitimate activations on migrated data; making it silent would hide that
the control did not run.

---

## D4 — A reserved-argument collision is rejected, not silently reordered

Fixing B2 (MCP `params.resource` overriding the authorized resource) had
two candidate shapes: reorder the spread so the canonical value wins, or
reject the request.

**Decided:** reject, and _also_ reorder as defence in depth.

**Why:** reordering alone makes the canonical value win but quietly
discards what the caller actually asked for. The result is a request that
did something other than what it said, with no error — the same class of
dishonesty as the original defect, relocated. A collision is either a
caller bug or an attack; both deserve a refusal.

**Ruled out:** requiring `additionalProperties: false` on every stored
`inputSchema`. That is the right long-term fix and is on the list, but it
is a data migration across every registered tool action and would not have
protected the reserved names anyway — a schema author can always omit it.

**Also decided in the same change:** the argument-collision check sits with
the other pure input validation, _ahead of_ the SSRF check and the
transport. That ordering makes it unit-testable without a network fake,
which is why the regression test can assert the refusal happens before any
outbound connection is attempted.

---

## D5 — The BFF's CSRF rule is written around what a request demonstrably is

`manar-web`'s Server Components legitimately call the BFF server-to-server
via `getServerApiClient(origin)`, with no browser headers at all. A naive
"require `Origin` on every mutation" rule would break server-side
rendering.

**Decided:** for non-GET methods, trust `Sec-Fetch-Site` when the browser
sends it (allow only `same-origin`); when it is absent _and_ `Origin` is
absent, treat the request as non-browser and allow; when `Origin` is
present without `Sec-Fetch-Site`, require an exact origin match.

**Why `none` is rejected:** it means a user-typed URL or a bookmark, which
is never how this app performs a mutation.

**Why GET is not checked:** the reason a cross-site GET was dangerous is
that it could be aimed at an attacker's host, and that is fixed in
`buildUpstreamUrl`. Adding a CSRF check on GET would break ordinary
navigation without closing anything.

---

## D6 — AI systems are a new first-class record, not an extension of `Agent`

**Decided:** `AiSystem` is its own model, and `AiSystemAgentLink` is an
additive, attributed, reversible assertion that an agent serves it.

**Why not extend `Agent`:** an agent is a runtime security principal with a
certificate and a lifecycle driven by enrollment and revocation. A governed
AI system is a business record with an accountable owner, a review date and
a risk rationale, and it routinely maps to several agents or to none yet.
Folding one into the other would force every governance field onto rows
that have no owner, and would make "retire the governance record" and
"revoke the workload identity" the same operation, which they must not be.

**Why link rows never rewrite the agent:** brief §3.1 requires that
existing agents can be linked "without inventing or losing ownership
information". `Agent.createdBy` is untouched by linking.

---

## D7 — Additive-only schema change for the first slice

The `20260908070000_add_ai_system_inventory` migration adds five tables,
two enums and one nullable column. It drops nothing and alters no existing
column's type or nullability.

**Why it matters:** brief §8 requires expand/migrate/contract plans and
warns against assuming every migration is reversible. This one is in the
expand phase and is reversible by dropping the new objects, which is worth
preserving while the surrounding features are still moving. The
`Incident.aiSystemId` column is nullable specifically so that an incident
opened from raw audit evidence, before anyone has established which
governed system it belongs to, does not require a fabricated attribution.

---

## D8 — Bring up the local Compose stack rather than reasoning from source

Brief §11 forbids replacing runtime evidence with "the code looks correct",
and several gates (e2e suites, OpenAPI regeneration for `manar-web`'s typed
client, browser screenshots) cannot run without a live stack.

**Decided:** start the documented `pnpm infra:up` developer stack locally.
Only `up` operations. No volume pruning, no `docker system prune`, no
removal of anything — the workspace records a prior incident in which
another project's Docker volumes were deleted during cleanup, and that
class of action is out of scope here regardless.

**Not decided by this:** nothing is deployed anywhere. Customer
infrastructure, credential rotation, pushes and merges remain outside what
this brief authorises.
