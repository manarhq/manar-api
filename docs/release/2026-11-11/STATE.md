# Release 2026-11-11 — execution state

**Purpose.** The single resumable state file for the production release
program described in `Manar_Claude_Code_Production_Brief.md` (workspace
root). Read this first after a context reset. Plan lives in `PLAN.md`,
blockers in `BLOCKERS.md`, decisions in `DECISIONS.md`, raw gate output in
`evidence/`.

Last updated: 2026-09-08.

## 1. Coordinated branches

All three repositories carry one coordinated branch. Nothing is pushed; no
merges into `main`, no force-pushes, no deploys (brief §2). All release
work is currently **uncommitted working-tree change** on these branches.

| Repository  | Branch               | Base commit |
| ----------- | -------------------- | ----------- |
| `manar-api` | `release/2026-11-11` | `4ab3be2`   |
| `manar-web` | `release/2026-11-11` | `9e63767`   |
| `manar-ai`  | `release/2026-11-11` | `93074c2`   |

Pre-existing divergence handled at session start: `manar-api` local `main`
was ahead 1 / behind 1 of `origin/main`, where the "behind" commit is a
merge whose content was already present locally — so local content is a
strict superset and the branch was cut without merging (see `DECISIONS.md`
D1). `manar-web` was 2 behind with a clean tree and was fast-forwarded
first. `manar-ai` was in sync. All three trees were clean at branch
creation.

## 2. Completed slices

| #   | Slice                                                                   | Repos    | Status             |
| --- | ----------------------------------------------------------------------- | -------- | ------------------ |
| 0   | Baseline: bootstrap, gates, route/dependency inventory, security triage | all      | **done**           |
| 1   | AI-system inventory: schema, migration, service, API, tests             | api      | **done (backend)** |
| 2   | The two critical security defects                                       | web, api | **done**           |
| 3   | Auth, egress, reliability, deployment, AI transport/DLP blockers        | api, ai  | **done**           |
| 4   | Approval context: the reviewed parameter snapshot, end to end           | api      | **done (backend)** |
| 7   | Design system: density + theme-from-system-preference                   | web      | **done**           |
| 8   | AI-systems console surface                                              | web      | **done**           |

### What landed

**Slice 1 — AI-system inventory (`manar-api`).** Five new tables, two
enums, one nullable FK on `Incident`; `AiSystemsService` with a
server-enforced lifecycle edge table, separation of duties on
`REVIEW → ACTIVE`, and material-change versioning inside the same
transaction as the update; nine endpoints under `/ai-systems`. Runtime
coverage is **derived per read** from real `ToolInvocation` rows and
`Agent.status`, never stored — see `DECISIONS.md` D2. 33 unit tests.

**Slice 2 — the two ship-stoppers.**

- `manar-web` BFF upstream host injection (B1): a `%2F`-prefixed catch-all
  segment made the upstream URL protocol-relative, sending the user's
  access token to any attacker-named host. Fixed in
  `lib/api/bff-request.ts` with segment validation, re-encoding, an origin
  invariant enforced twice, a forwarded-header denylist, and a CSRF rule
  that still permits this app's own server-to-server calls. 23 tests.
- `manar-api` MCP resource clobbering (B2): caller `params` were spread
  _after_ the authorized `resource`, so Manar authorized and audited one
  target while the MCP server acted on another. Now rejected outright, with
  canonical fields spread last as defence in depth and the whole
  connect→invoke→close lifecycle bounded. 5 tests, no network.

**Slice 3 — remaining blockers.** JWT audience/algorithm/`typ` pinning
(verified empirically against how this realm actually shapes tokens —
`azp`, not `aud`); constant-time secret comparison; redirect-aware SSRF
with credential stripping on cross-origin hops and a response size limit;
dependency-aware readiness that keeps optional-AI degradation out of the
failure path; health-route throttler exemption plus a documented fail-open
on rate-limit storage; graceful shutdown in both processes and both charts;
keyset-paginated chain verification proven to still detect tampering in the
second batch; bootable Helm charts. In `manar-ai`: gRPC mTLS with peer
verification and a production plaintext refusal; environment-gated,
authenticated debug surface with the Dockerfile default flipped to the gRPC
target; and deterministic redaction before any external model call, with
the detection cost measured rather than asserted.

**Slice 4 — approval context.** `ApprovalRequest` now persists the risk
_breakdown_ (deterministic vs AI score, reason codes, the ceiling
compared against, and why approval was required — persisted rather than
derived, because a matched ALLOW rule also records a `policyVersionId`).
New `GET /approvals/:id` returns the reviewed snapshot: redacted
parameters with every withheld path named, the `parameterDigest` the grant
binds to, attribution-split reason codes, and the action's expected effect.

## 3. Test evidence

Full detail in `evidence/2026-09-08-gates.md`. Summary:

| Repo | Gate                     | Baseline             | Now                                                  |
| ---- | ------------------------ | -------------------- | ---------------------------------------------------- |
| api  | unit                     | 160 passed, 2 failed | **305 passed, 0 failed**                             |
| api  | e2e                      | **NOT-RUN**          | **168 passed, 0 failed** (deterministic over 3 runs) |
| api  | typecheck / build        | pass                 | pass                                                 |
| api  | migrations on a clean DB | not verified         | **17 applied, no drift**                             |
| ai   | mypy (strict) / ruff     | pass                 | pass                                                 |
| ai   | pytest                   | 73 passed, 3 skipped | **107 passed, 3 skipped**                            |
| web  | lint / typecheck / build | pass                 | pass                                                 |
| web  | tests                    | 17 passed            | **153 passed**                                       |

Two failures were found and fixed during the e2e run rather than absorbed:
a genuine regression (a clock tolerance that let expired tokens through —
the tolerance was removed, not the assertion) and an intentional contract
change (`/health/ready`, whose test was rewritten to assert the contract
including the optional-dependency invariant). Both are written up in the
evidence file.

Six further e2e failures turned out to be one environmental cause: the host
disk is at 95%, so OpenSearch flood-staged the audit index read-only.
Resolved by raising watermarks and clearing the block — **no data deleted,
no volumes removed.**

## 4. Open release blockers

`BLOCKERS.md`. Two of the top three are fixed (B1, B2). B3–B5, B7, B14–B21
remain open; B6, B8–B13, B16, B22 are fixed or substantially addressed.

The gates that cannot close from this workspace, and why, are listed at the
end of `evidence/2026-09-08-gates.md`: no vendor integration has been
verified against a real service, no performance/recovery exercise has been
run, no accessibility assessment has been run, and the AI quality corpus
does not exist. These need owner input or an environment that does not
exist here — see `PLAN.md`'s schedule assessment.

## 5. Decisions

`DECISIONS.md` (D1–D8). No foundational technology has been substituted, so
no ADR has been required yet.

## 6. Next executable step

Slices 1–4, 7 and 8 are done, and `manar-api`'s gRPC client now carries the
`AI_ADVISORY_TLS_*` configuration manar-ai's mTLS listener needs (defaulting
off, so the plaintext developer stack is unchanged).

In dependency order:

1. **Slice 5 — findings/anomaly detection.** The largest remaining product
   investment and the one everything in `PLAN.md` after it depends on. The
   first three detectors are chosen by what telemetry actually exists; see
   `PLAN.md` for which candidates are deliberately excluded and why.
2. **Slice 10 — the decision explorer**, which also closes B19: the
   `/authorization` route is still a visible `NotImplementedPage` with a
   live sidebar entry, and brief §11's gates forbid that in the release
   surface.
3. **Slice 6 — server-side aggregates**, closing B20: the overview and
   command palette still compute from page-one data.
4. **Two integration verifications that need no external access** and would
   move real gates: a genuine local Ollama inference run (`pnpm infra:up:ai`
   — note the model pull needs several GB, so check disk headroom first),
   and an actual mTLS handshake between manar-api and manar-ai.

Owner input needed, and needed early because it is the item most likely to
move the date: **which vendor integrations are in release scope**, given
that every connector in this workspace is a demo fixture. See
`INTEGRATION-MATRIX.md`.
