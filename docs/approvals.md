# Approval engine (Temporal)

This is `manar-api`'s implementation of Phase 8 (Approval Engine):
`docs/superpowers/specs/2026-08-19-phase8-approvals-design.md`, Sections
27, 28, and 31. It gives `REQUIRE_APPROVAL` — a dead end since Phase 6
(`docs/policy-model.md`) and still a dead end through Phase 7b
(`docs/tool-gateway.md`) — a real fulfillment path: a durable Temporal
workflow, a human decision endpoint, and a short-lived signed grant that
lets the agent's retried request actually execute, exactly once, for
exactly the parameters it was approved for (Section 80: approval replay
and parameter binding are mandatory invariants, not optional coverage).

## Local infra: Temporal

`deploy/docker-compose.yml` adds `temporal` (`temporalio/auto-setup:1.29.0`)
and `temporal-ui` (`temporalio/ui:2.36.0`), following the same "nothing
ephemeral, share the existing Postgres" posture every other service in
that file already uses (Keycloak/OpenBao are the exceptions, for reasons
specific to each — see that file's own header comment) — unlike OpenFGA,
which needed a separate `openfga-db-init` job because its own image has no
database-creation step, `temporalio/auto-setup`'s entrypoint creates its
`temporal`/`temporal_visibility` databases itself (`temporal-sql-tool
create`) against the same `manar`/`manar` credentials every other service
uses, so no separate init job is needed here. `DB=postgres12` is the
correct driver value for any Postgres major version ≥ 12 per Temporal's
own docs — not tied to literally running Postgres 12 (this file runs
Postgres 18). The server auto-creates and uses its `default` namespace.
`temporal-ui`'s host port is `8083` (not the image's own default `8080`,
already claimed by OpenFGA's HTTP API) — local inspection only, never
required by any app code or test.

## Data model (tenant DB)

`prisma/tenant.prisma`, migration `20260818213801_add_approval_engine`:

- **`ApprovalRequest`**: `id`, `taskId`/`agentId` (FKs), `toolId`/
  `actionId`/`resource`/`params` (the _exact_ values from the original
  `POST /agent/v1/tools/invoke` request that triggered this approval —
  never re-derived), `riskScore`, `policyVersionId` (FK, nullable — a
  `REQUIRE_APPROVAL` decision can come purely from `RiskEngine`'s score
  exceeding `task.riskCeiling` with no policy rule matching at all, in
  which case there's no version to record), `status` (`PENDING | APPROVED
| DENIED | EXPIRED`), `requestedAt`, `expiresAt` (this request's own
  timeout — `APPROVAL_REQUEST_TTL_MS`, 30 minutes by default),
  `temporalWorkflowId` (unique — the 1:1 `ApprovalWorkflow` run this
  request is bound to).
- **`ApprovalDecision`**: `id`, `approvalRequestId` (FK), `approverId` (FK
  `UserProfile`), `decision` (`APPROVE | DENY`), `reason`, `decidedAt`.
  Modeled 1:many even though this phase only ever produces one row per
  request (decision #33: one approver) — this is what lets a future N-of-M
  approval chain be added without a schema migration; N-of-M logic itself
  is out of scope this phase.
- **`AuthorizationGrant`**: `id` (this **is** the JWT `jti`),
  `approvalRequestId` (FK, `@unique` — at most one grant per request,
  ever), `taskId`/`agentId`/`toolId`/`actionId`/`resource`,
  `parameterHash`, `policyVersionId` (nullable, same condition as
  `ApprovalRequest`'s), `riskScore` (as of _re-evaluation_, not
  necessarily equal to the original request's), `issuedAt`, `expiresAt`
  (`APPROVAL_GRANT_TTL_MS`, 5 minutes by default), `consumedAt` (nullable
  — single-use), `revokedAt` (nullable, **unused this phase** —
  kill-switch-driven grant revocation is a dedicated later phase; the
  column exists now so that phase needs no migration).

## The flow, end to end

1. Agent calls `POST /agent/v1/tools/invoke` (no `grantToken`) →
   `AuthorizationService.authorize` (Phase 5/6, entirely unchanged) yields
   `REQUIRE_APPROVAL` → `ToolInvokeController` creates an `ApprovalRequest`
   row and starts a Temporal `ApprovalWorkflow` (workflow ID
   `approval-<uuid>`, distinct from the `ApprovalRequest.id` itself),
   responds **202** `{ status: 'PENDING', reason, riskScore, approvalId }`.
   **No tool call happens at this point** — `ToolInvokeController`'s
   `startApproval` method never calls `CredentialBrokerService` at all
   (Section 80's "pending action cannot execute before approval"
   invariant). `status: 'PENDING'` deliberately keeps Phase 7b's own
   response shape intact for existing callers/tests; `approvalId` is this
   phase's addition.
2. A human calls `POST /approvals/:id/decide { decision, reason }`
   (JWT-guarded, role `APPROVER`/`SECURITY_ADMIN`/`TENANT_OWNER`) →
   `ApprovalsController` signals the running workflow's `decide` signal
   with `{ decision, approverId: <the caller's UserProfile.id>, reason }`.
   The handler itself never writes an `ApprovalDecision` row or flips
   `ApprovalRequest.status` (see "Workflow code has no I/O" below) — but
   as of Phase 14 (security cleanup 1, closing a response-accuracy gap
   Phase 11b Part 2 found), it does not return immediately after sending
   the signal either. It synchronously awaits the workflow's actual
   terminal result (`WorkflowHandle.result()`, bounded by
   `APPROVAL_DECIDE_RESULT_TIMEOUT_MS`) and reports _that_ real outcome.
   This matters because `ApprovalWorkflow`'s `decide` signal handler is
   "first signal wins" (step 3 below): for two genuinely concurrent
   `decide` calls on the same request, both signal successfully and both
   await the same `result()` promise, so both responses correctly report
   the one decision that actually won the race — never a decision that
   was silently discarded. See `ApprovalsController.decide`'s doc comment
   for why this, not applying Phase 12a's `Idempotency-Key` interceptor,
   is the correct fix (that interceptor dedupes retries of one identical,
   caller-keyed request — it doesn't help two different concurrent
   requests with no shared key, which is exactly this scenario).
3. `ApprovalWorkflow` (`src/temporal/workflows/approval.workflow.ts`) was
   racing a `condition()` on that signal against its own `expiresAt`
   timeout (`Promise`-style `condition(predicate, timeoutMs)`, the
   TypeScript SDK's documented pattern for "wait for a signal or a
   timeout, whichever comes first"). On `DENY`: runs the
   `finalizeApprovalDecision` Activity, which records the `ApprovalDecision`
   row and sets `ApprovalRequest.status = DENIED`. No grant.
4. On `APPROVE`: the same Activity first records the `ApprovalDecision`,
   then — **before ever issuing anything** — re-evaluates:
   - the task is still `ACTIVE`, within its time window, and under its
     execution limit (`TasksService.evaluateFullLiveness`);
   - the agent is still `ACTIVE`;
   - a **fresh** `PolicyEngine.evaluate`/`RiskEngine.score` call against
     _current_ published policy state — never trusting the original,
     possibly-stale decision (Section 27: "don't assume an action remains
     safe because approval happened N minutes ago"). If the fresh
     evaluation now says `DENY` (a policy was republished stricter while
     the request was pending, for example), re-evaluation fails and
     **no grant is issued even though the human clicked approve** —
     `ApprovalRequest.status = DENIED`. If it still says anything else
     (`ALLOW` or even still `REQUIRE_APPROVAL` — a human already decided
     that part), re-evaluation succeeds.

   On success: atomically increments `Task.executionCount` (the exact
   same conditional-`UPDATE` race-closing pattern
   `AuthorizationService`'s own `ALLOW` path uses — hoisted into
   `TasksService.incrementExecutionCount` so both call the one
   implementation) — an approved-but-never-executed action still costs one
   execution slot, the moment it's actually granted, not later when
   consumed. Then issues an `AuthorizationGrant`: `id`/`jti`, tenant,
   agent, task, tool, action, resource, the re-evaluated policy version and
   risk score, `issuedAt`/`expiresAt` (5-minute TTL), and a `parameterHash`
   binding it to the _exact_ `params` the original `ApprovalRequest`
   recorded. `ApprovalRequest.status = APPROVED`.

5. If nobody signals before `expiresAt`: the workflow's own timeout branch
   runs the `expireApprovalRequest` Activity — `ApprovalRequest.status =
EXPIRED`. No `ApprovalDecision` row (nobody decided) and no grant is
   ever issuable for this request again.
6. The agent polls `GET /agent/v1/approvals/:id` (mTLS-guarded). This
   endpoint reads `ApprovalRequest`/`AuthorizationGrant` state directly —
   it never queries the workflow itself (no Temporal query handler exists;
   the workflow's own Activities are the only thing that ever writes these
   rows). It answers 404 (not 403) if `approvalRequest.agentId` doesn't
   match the mTLS-authenticated caller, so a grant can never leak across
   agents even if one agent somehow learned another's `ApprovalRequest.id`.
   Once `status` is `APPROVED` and the grant is still unconsumed/unexpired,
   the response includes a freshly re-derived `grantToken` (see "The grant
   token" below) and `grantExpiresAt`.
7. The agent retries `POST /agent/v1/tools/invoke` with the _same_ body
   (`taskId`/`toolId`/`actionId`/`resource`/`params`) plus `grantToken`.
   Its presence — not a separate flag — is what routes the request onto
   the redemption path: `GrantService.verifyGrant`, then
   `AuthorizationService.authorizeRedemption` (2026-10-07, S6/F7).
   `verifyGrant` checks, in order: signature/expiry (`jose.jwtVerify`); the decoded claims match
   _this_ request's `agentId`/`taskId`/`toolId`/`actionId`/`resource`
   exactly; `parameterHash` recomputed from _this exact request's_
   `params` matches (Section 80's parameter-binding invariant — change
   even one nested value and the grant is rejected); the persisted
   `AuthorizationGrant` row itself is unconsumed/unrevoked/unexpired.
   `authorizeRedemption` then re-runs the full decision against current
   state: kill switches at every level and AI-system suspension, task
   assignment, liveness and TTL (ancestors included), forbidden actions,
   OpenFGA, and the current policy version. A policy `DENY` refuses; a
   policy `APPROVAL_REQUIRED` and the risk ceiling do not, because a human
   approved this exact request. It does not increment `executionCount`
   again (that happened at grant issuance, and the task's own limit does not
   count this request twice). Every outcome is a `Decision` row
   (`stage = GRANT_REDEMPTION`). On ALLOW the grant is marked consumed
   (`UPDATE ... WHERE consumedAt IS NULL AND revokedAt IS NULL AND
expiresAt > now`) in the same transaction as that row, and the request
   proceeds to `CredentialBrokerService.invoke` under the decision's id.
8. A consumed, expired, revoked, or parameter-mismatched grant used again
   → `403 { decision: 'DENY', reason: 'grant_already_consumed' |
'grant_expired' | 'grant_revoked' | 'grant_mismatch' | ... }`. No tool
   call is ever attempted.

## The grant token

An `AuthorizationGrant` is signed as an HS256 JWT
(`src/approvals/grant-token.util.ts`, using `jose`'s `SignJWT`/`jwtVerify`
— the same library `JwtAuthGuard` already uses to _verify_ Keycloak
tokens, here used to both sign and verify a token this service issues
itself). Claims: `jti` (= `AuthorizationGrant.id`), `tenantId`, `agentId`,
`taskId`, `toolId`, `actionId`, `resource`, `parameterHash`, `iat`/`exp`
set explicitly from the grant's own `issuedAt`/`expiresAt` columns (never
"now" at signing time).

**No signed token string is persisted anywhere.** Signing is fully
deterministic given the same claims + the same `iat`/`exp` + the same
`APPROVAL_GRANT_SIGNING_SECRET` — `GET /agent/v1/approvals/:id` simply
re-derives the token from the `AuthorizationGrant` row every time it's
called, rather than storing (and risking drifting from) a second copy of
the same information. `APPROVAL_GRANT_SIGNING_SECRET` must be identical
across the HTTP processes and the worker process (both sign/verify
grants) — see `.env.example`.

## `ApprovalWorkflow`: workflow code has no I/O

`src/temporal/workflows/approval.workflow.ts` does exactly three things:
registers a `decide` signal handler, races `condition(() => signal
received, timeoutMs)`, and calls one of two Activities based on the
outcome. No database access, no HTTP calls, no crypto — every stateful
operation lives in `src/temporal/activities/approval.activities.ts`
(Section 28). This is enforced structurally, not just by convention: the
workflow file imports `ApprovalActivities` (the Activity _interface_, in
`approval-activities.interface.ts`) with `import type` only, which
TypeScript's `isolatedModules` erases completely from the compiled
output — the real implementation (`GrantService`, Prisma queries, `jose`
signing) is never part of what Temporal's `Worker.create` bundles into
the workflow's deterministic sandbox, even though both files sit right
next to each other on disk.

A second `decide` signal received after the first is silently ignored —
first decision wins; there is no code path that sends a second signal for
a request whose `ApprovalRequest.status` is no longer `PENDING` anyway
(`ApprovalsController` checks this before ever signaling), but the
workflow itself doesn't assume that.

## The worker: its own process

Per Section 28, the workflow runtime (and every Activity it calls) never
shares an event loop with the Fastify HTTP server `src/main.ts` boots.
`src/worker.main.ts` is a separate entry point (`pnpm worker` in dev,
`node dist/worker.main.js` / `pnpm worker:prod`, or the Dockerfile's
`worker` stage — the same built image as the HTTP server's `runtime`
stage, with only its `CMD` different, so either can be deployed and scaled
independently):

1. Bootstraps `WorkerAppModule` as a plain Nest **application context**
   (`NestFactory.createApplicationContext` — no HTTP listener of any kind;
   this module imports no controller-bearing module at all) purely to get
   real, DI-wired instances of the _exact same_ providers the HTTP
   processes use: `TenantDatabaseManager`, `PolicyEngine`, `RiskEngine`,
   `TasksService`, `GrantService`. `ApprovalActivitiesFactory.build()`
   wraps those into the plain `{ activityName: asyncFunction }` object
   `@temporalio/worker`'s `Worker.create({ activities })` wants.
2. Connects to Temporal (`NativeConnection.connect`) and creates a
   `Worker` polling `TEMPORAL_TASK_QUEUE` (`manar-approvals` by default),
   with `workflowsPath` pointing at the compiled `approval.workflow.js`
   sitting next to this file — Temporal's own bundler re-bundles whatever
   that path resolves to into an isolated sandbox itself, so it doesn't
   matter that the source `.ts` file has only type-level references to the
   real Activity implementation.
3. `worker.run()`, with `SIGINT`/`SIGTERM` wired to a graceful
   `worker.shutdown()`.

## Interaction with `AuthorizationService` (Phase 5/6, unchanged logic)

`AuthorizationService.authorize` itself is untouched — Phase 8 only
extends its `REQUIRE_APPROVAL` return value with an additional
`policyVersionId: string | null` field (which `PolicyEngine`'s own
`PolicyEvaluationResult` already computed; `AuthorizeController`'s
existing behavior on `POST /agent/v1/authorize` is unaffected — that
endpoint still returns `{ decision, reason, riskScore }` shaped exactly as
before, the SDK's own response typing is a type-only cast with no runtime
schema check, so an additional field is invisible to every existing
caller). `TasksService.incrementExecutionCount` (previously a private
method on `AuthorizationService`) was hoisted into `TasksService` so
`GrantService`'s grant-issuance path can perform the exact same
race-closing increment, once, without a second copy of that logic.

## Testing

`src/temporal/workflows/approval.workflow.spec.ts`: `@temporalio/testing`'s
time-skipping `TestWorkflowEnvironment` — approve, deny, timeout/expiry,
a defensive "grantId-less APPROVED activity result still resolves to
DENIED", and "a second signal is ignored" — all against mocked Activities,
proving the workflow's own control flow independent of any real database.
The timeout scenario in particular is exactly what the time-skipping
environment is for: observing a 30-minute-default timeout in about a
second of real wall-clock time rather than actually waiting it out.

`test/approvals.e2e-spec.ts`: real Postgres/Keycloak/OpenBao/OpenFGA/
Temporal (`pnpm infra:up`), a real Temporal `Worker` bootstrapped
in-process against the real local Temporal server (the SDK doesn't care
whether the worker process is literally a separate OS process or a
separate in-process `Worker` instance — this test suite runs one the same
way `src/worker.main.ts` would, just co-located with the test for
convenience, mirroring how `test/tool-gateway-demo-integration.e2e-spec.ts`
already boots both Nest apps in-process), and the real
`packages/demo-soc-tools` fixture from Phase 7b's own integration test:

- Full flow: invoke → `PENDING_APPROVAL` (202, `approvalId` present) →
  decide `APPROVE` → poll until `APPROVED` → grant token returned → retry
  invoke with the grant → the tool actually executes against the real
  demo host, independently re-verified.
- Decide `DENY` → `ApprovalRequest.status = DENIED`; retrying invoke
  without a grant still requires approval (a fresh `REQUIRE_APPROVAL`),
  never executes.
- **Approval replay**: reusing an already-consumed grant → denied,
  `grant_already_consumed`, no second tool call.
- **Parameter binding**: a grant issued for one `resource`, retried with a
  different `resource` (same grant token otherwise) → denied,
  `grant_mismatch`, no tool call — Section 80's mandatory invariant.
- A grant used after its own short expiry (`APPROVAL_GRANT_TTL_MS` set to
  a few hundred milliseconds for this test) → denied, `grant_expired`.
- An `ApprovalRequest` that nobody decides before its own short
  `APPROVAL_REQUEST_TTL_MS` → workflow completes `EXPIRED`; polling shows
  `EXPIRED`, no grant token ever appears.
- **Policy changed mid-flight**: a policy republished stricter (`DENY`)
  between the original request and the human's `APPROVE` decision → grant
  is not issued even though the human clicked approve — proves Section
  27's re-evaluation requirement is real, not decorative.
- Phase 5/6/7 e2e suites (including `test/tool-gateway-demo-integration.e2e-spec.ts`)
  re-run and pass unmodified.

## Out of scope this phase

- N-of-M / multi-approver chains (`ApprovalDecision`'s 1:many shape allows
  it later; no such logic exists).
- Approval dashboard UI (Phase 11) — decision is an API call only.
- Kill-switch-driven grant revocation (a dedicated later phase) — the
  `revokedAt` column exists, nothing sets it yet.
- Slack/Teams/email/ServiceNow approval channels.

## 8-hour grants, device approvals and push (launch, spec 4.6)

- **Approve for 8 hours** (`decision: "approve_8h"` on `POST /approvals/:id/decide`, or on
  `POST /host-approvals/:id/decide`): creates an `ApprovalAllowGrant` for one device or agent, one
  tool, one action and one exact resource string, for 8 hours. `AuthorizationService` looks it up
  after OpenFGA and before policy evaluation; it satisfies a policy approval requirement or the risk
  ceiling and nothing else (a policy DENY, kill switches, OpenFGA and task limits still decide first).
  Audit: `approval.grant.created`, `approval.grant.used`. The old `APPROVE | DENY` values still work.
- **Approve + make rule**: `makeRule: true` returns `ruleDraft`, an ALLOW rule with the exact resource.
- **Device approvals**: `HostApprovalsService.open()` is what the host authorize path calls when the
  answer is "ask". WARDEN reads `GET /host/v1/approvals/pending` and answers with
  `POST /host/v1/approvals/:id/decide`. Refused (403) when the host is not APPROVED, when its owner
  has no approver role in this workspace, and for `highRisk` approvals (`high_risk_open_in_console`).
- **Web Push**: `VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY`, `VAPID_SUBJECT` (ExternalSecret keys; all or
  none). `GET /push/vapid-key`, `POST|DELETE /push/subscriptions`. A push goes to subscribed approvers
  of the workspace when an approval opens; `PushService.notifySecretAlert` is for the secrets track.
  Payloads carry no resource path, prompt or secret. 404 and 410 answers delete the subscription.
- **Phone (push buttons and Telegram)**: a push for a device approval carries a per-subscriber signed token
  (HMAC keyed from `APPROVAL_GRANT_SIGNING_SECRET`, bound to the approval, the person, the workspace and the
  approval's expiry). Every phone message shows the tool, the action type and a 4-character match code
  (`#3F2B`, also on the device prompt via the stored summary and `matchCode` in `/host/v1/approvals/pending`),
  never the resource; one push tag per approval. The service worker posts it with the person's session to `POST /phone/push-decide`;
  both must agree, the approver role and risk are re-checked first, and the token is spent (`phone_action_uses`, tenant DB) in the
  same transaction as the decision, so a refused press never burns it, and
  `highRisk` approvals and `approve_8h` are refused (`via: push`). Telegram: `TELEGRAM_BOT_TOKEN`,
  `TELEGRAM_WEBHOOK_SECRET` (ExternalSecret keys), `TELEGRAM_BOT_USERNAME`, `TELEGRAM_WEBHOOK_URL`. Console:
  `GET|POST|DELETE /telegram/link` (status, 10-minute one-time code, unlink). `POST /telegram/webhook` is public but
  answers only with the secret header (401), is 404 when the bot is off, and is rate limited. `callback_data` is
  `a.<approval id>.<y|n>.<sig>`; the signature binds the chat, workspace and person (not carried in the data), so a forwarded button, or one
  left from before the chat was re-linked, does nothing. A chat linked to another person must `/stop` first; a new
  link names the workspace and tells the person's other chats. When an
  approval is decided on any channel or times out, the Telegram message loses its buttons (decide path and a
  15-second sweep) and a closing push removes the notification. Audit: `telegram.link.created|removed`.

### Hardening after review

- Device decisions are `approve_once` or `deny` only. `approve_8h` is a console decision (403
  `eight_hours_in_console` from a device). The secrets vault never gets consent from the device:
  `POST /host/v1/approvals/vault` opens a high-risk approval that only the console can decide.
- Push endpoints are limited to the browsers' push services (FCM, Mozilla, WNS, Apple), https, port
  443, no IP literals; checked on subscribe and again on every send.
- Who may approve is read from current memberships when the `memberships` table exists (role
  bindings only as a fallback before the identity migration), at device decide and push fan-out.
- A device cannot flood the queue: the same pending request is reused, 20 new approvals per 10
  minutes per device at most, one push tag per device.
- "Approve + make rule" gives no draft for `*` or a trailing `*`, so it never widens an approval.
- Residual risk: the WARDEN prompt is a desktop prompt. Code running as the same user (the AI tool
  itself, a postinstall script) shares that desktop and is not fully isolated from it. Mitigations:
  only the installed, root-owned binary may connect as the helper; the device can only approve
  once; anything standing or touching secrets is decided in the console.

## History, revoke and who decides (3 Nov 2026)

**Who decides** (`src/approvals/decision-rights.ts`).

- An approver role (`TENANT_OWNER`, `SECURITY_ADMIN`, `APPROVER`) decides any request, except a
  _sensitive_ request from their own device or agent in a company workspace: another approver must
  answer it ("Ask another approver, or deny it"). There is no bypass. A personal workspace has one person: its owner may approve their own sensitive
  request (once, never 8 hours or always) only in the console and only within
  `STEP_UP_MAX_AGE_SECONDS` (15 min) of an interactive sign-in (`auth_time`, checked on the server;
  otherwise 401 `reauth_required` and the console sends them through sign-in and back). It is
  recorded as `selfConfirmedAt` and audited as self-approved, high risk, re-confirmed.
- The device owner, or the agent's creator, may approve once or deny their own _routine_ requests
  in the signed-in console, if they hold a role that operates agents now (`OPERATOR_ROLES`; a
  demoted or removed person loses it even though `createdBy` still names them), and unless the
  company workspace set `approvalsAdminsOnly` (`PATCH /tenant/settings`). A sensitive request they
  can only deny. 8 hours, always and "make rule" stay with approvers.
- Sensitive: a device approval flagged `highRisk`, an agent request scoring
  `AGENT_HIGH_RISK_SCORE` (60) or more, or an action that hands over a secret (`HANDOVER_ACTIONS`).
  Collecting a handover (`POST /approvals/:id/handover`) stays approver-only.
- Off the console (WARDEN on the device, push, Telegram) only an approver decides: a process on the
  device can answer a device prompt, so the device credential alone is never consent.

`HostApprovalsService.decide` enforces this for every device channel and `ApprovalsController` for
agent requests. Lists, history and detail show a person who is not an approver only their own
devices and agents; each item carries `allowedDecisions`, `needs` and `why` so the console shows
only what the person may do and says why not.

**History.** `GET /approvals/history`: agent and device approvals in one cursor, every state
(`PENDING`, `APPROVED`, `DENIED`, `EXPIRED`, `REVOKED`), with who decided, when, through which
channel, the end reason (`no_answer`, `paused`, `withdrawn`, `superseded`, or a re-evaluation
reason), when the device or agent received it, and what it created (8-hour grant, site rule, block).
A device that stops waiting now withdraws its prompt (`withdraw: true`); it is recorded as
EXPIRED `withdrawn`, not as a person's deny; older rows written as a device deny of a new site
are shown the same way (the rows are not rewritten).

**Revoke.** `POST /approvals/:id/revoke`, `POST /host-approvals/:id/revoke`:

| State when revoked                                                | Result                                                                                                                                                                                                                |
| ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Not yet received (`releasedAt` / `usedAt` null, grant unconsumed) | `REVOKED`, `usedBeforeRevoke: false`. The grant is revoked; the device or agent reads `REVOKED` and refuses. Nothing ran.                                                                                             |
| Already received                                                  | `REVOKED`, `usedBeforeRevoke: true`. An incident (HIGH) and a push to approvers; this exact action is blocked (`ApprovalAllowGrant.effect = BLOCK`, 30 days, or a DENY site rule for a site) until a person lifts it. |
| Either                                                            | Any 8-hour grant or remembered site rule it created is withdrawn.                                                                                                                                                     |

"Received" is one conditional update racing the device's or agent's own read, so a revoke is never
reported as "cancelled" for an approval the device already saw. `POST
/approvals/allow-grants/:id/revoke` withdraws an 8-hour grant or lifts a block at any time; both
authorize paths read grants and blocks live, so it applies on the next request.

409 responses carry a `reason` (`paused`, `already_decided`, `expired`, `revoked`, `not_approved`,
`action_already_used`, `not_signaled`) next to a plain `message`.
