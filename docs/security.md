# Security controls (Phase 12a: Application Hardening & Webhooks)

This is `manar-api`'s implementation of Phase 12a:
`docs/superpowers/specs/2026-08-19-phase12a-app-hardening-webhooks-design.md`.
Eleven-plus prior phases built the actual security _architecture_
(tenancy, mTLS agent identity, OpenFGA/policy/risk authorization,
Temporal-backed approvals, the tamper-evident audit chain, the AI advisory
pipeline, kill switches); this phase is the hardening pass across that
architecture's edges — rate limiting, security headers/CORS, SSRF
protection, webhook delivery (a genuinely new capability, Section 51),
`Idempotency-Key` support, and closing a real, previously-unenforced data
residency gap (Section 54). See `docs/threat-model.md` for the
asset/threat/mitigation walkthrough this document's controls exist to
implement.

## Rate limiting (decision #76)

`@nestjs/throttler`, backed by a custom `ThrottlerStorage` implementation
(`RedisThrottlerStorageService`, `src/rate-limit/redis-throttler-storage.service.ts`)
against this codebase's existing `redis` (node-redis) client — reusing the
same library `RedisPubSubService` (Phase 9b) already established, rather
than adding a second Redis client (`ioredis`) purely to satisfy a
community Redis-throttler-storage package's peer dependency.

Two independently configured, independently scoped surfaces:

- **Human JWT surface** (`AppModule`): `TenantThrottlerGuard`
  (`src/rate-limit/tenant-throttler.guard.ts`), registered globally
  (`APP_GUARD`). Scoped **per tenant**, not per caller IP — a burst from
  one tenant's dashboard users behind a shared corporate NAT must not
  exhaust the same bucket as an unrelated tenant. Since this guard runs
  _before_ any controller-level `JwtAuthGuard`, it independently mirrors
  that guard's own first two steps (`docs/human-auth.md`): read the
  token's `iss` claim without verifying the signature, resolve it against
  `KnownIssuerRegistry` to a real `tenantId`. This is a rate-limit
  partition key, not a trust decision — a forged token at worst gets its
  own bucket, and still fails real authentication immediately afterward.
  Falls back to caller IP for any request it can't resolve a tenant for.
- **mTLS `/agent/v1/*` surface** (`AgentMtlsAppModule`):
  `AgentThrottlerGuard` (`src/rate-limit/agent-throttler.guard.ts`), scoped
  **per agent** — reads the client certificate's Subject Alternative Name
  identifier directly off the TLS socket (the same identifier
  `AgentMtlsGuard` itself later resolves against the database, but this
  guard runs first and doesn't repeat that DB work purely to pick a rate
  bucket).

Defaults (`RATE_LIMIT_HUMAN_TTL_MS`/`_LIMIT`, `RATE_LIMIT_AGENT_TTL_MS`/`_LIMIT`,
`src/rate-limit/rate-limit.config.ts`) are generous enough not to interfere
with normal dashboard/agent traffic while still bounding a genuine burst.

**Storage correctness**: `RedisThrottlerStorageService`'s Lua script
mirrors `@nestjs/throttler`'s own in-memory reference implementation
field-for-field (one Redis hash per key: `hits`/`expiresAt`/
`blockExpiresAt`/`blocked`, anchored to a client-supplied "now" rather than
multiple separate `PTTL` calls) — an earlier two-independent-Redis-keys
design had a real bug (caught by
`src/rate-limit/redis-throttler-storage.service.spec.ts`, run against real
Redis) where a caller could stay permanently re-blocked after its block
window expired but its hit-counter's own longer TTL hadn't. See that
file's own doc comment for the full failure mode.

## Security headers & CORS

`@fastify/helmet` (`src/security/setup-security.ts`), registered on
**both** Nest applications — security headers are reasonable defense in
depth on any HTTP surface, not just a browser-facing one. `contentSecurityPolicy`
is tightened for this being a JSON API (`default-src 'none'`) rather than a
page-serving app; must be registered _before_ the Fastify instance's
`.ready()` call (a Fastify plugin can never be added afterward), matching
where `src/main.ts`'s real bootstrap calls it, before `app.listen(...)`.

**CORS** (`src/security/cors.ts`, `resolveCorsOrigin`) — Section 99's
explicit hard rule: **no wildcard origin in production**. `CORS_ALLOWED_ORIGINS`
is a comma-separated allow-list; if `NODE_ENV === 'production'` and it's
still unset/`'*'`, the process **refuses to boot** rather than silently
falling back to something permissive. Outside production, `'*'` is honored
(reflects the caller's own `Origin` header) for local-dev convenience.
Applied only to the human-facing `AppModule` — the mTLS `/agent/v1/*`
surface has no browser CORS concept at all (agent SDKs present a client
certificate, never a browser `fetch`; Node's own `https` listener already
refuses any connection without one before CORS could ever run).

## SSRF protection

**The shared validator**: `assertSafeOutboundUrl`
(`src/common/ssrf/url-safety.ts`) is the one implementation every
outbound-URL-accepting surface in this codebase calls — never duplicated
per caller. Two checks, in order:

1. **Protocol allow-list**: only `http:`/`https:` — no `file:`, `ftp:`,
   `gopher:`, `data:`, etc.
2. **Address-range check**: the hostname is actually resolved (`dns.lookup`,
   injectable for testing — an IP literal resolves to itself instantly, so
   this one code path covers both "a raw private IP was registered" and "a
   hostname that resolves to one") and _every_ returned address is checked
   against loopback (127.0.0.0/8, ::1), "this network" (0.0.0.0/8), RFC 1918
   private space (10/8, 172.16/12, 192.168/16), link-local/metadata
   (169.254.0.0/16 — this is also the range the AWS/Azure/GCP instance
   metadata service lives in, 169.254.169.254 specifically), carrier-grade
   NAT (100.64.0.0/10), IPv6 unique-local (fc00::/7), IPv6 link-local
   (fe80::/10), and multicast/reserved (224.0.0.0/4+). A single unsafe
   address among several rejects the whole URL (fail closed).

**Re-validated at the actual moment of use, never cached** — a hostname
that resolved to a public address when a `Tool`/`WebhookEndpoint` was
first registered can be repointed (DNS rebinding) to resolve internally by
the time a real request is made. Every call site calls
`assertSafeOutboundUrl` fresh, immediately before the real network call:

- **`Tool.baseEndpoint`** (Phase 7b, never enforced until now):
  `HttpToolAdapter`/`McpToolAdapter` (`src/tools/`) call it immediately
  before their real `fetch`/MCP-transport-connect. There is still no
  human-facing `Tool` registration API (`docs/tool-gateway.md`'s own
  "out of scope" note, unchanged this phase) — `Tool` rows are only ever
  created by direct DB writes (tests, or a future operator tool), so this
  phase's retrofit is necessarily a call-time-only check for tools; a
  future registration API must call the same validator at creation too.
- **`WebhookEndpoint.url`** (new this phase): checked at **both**
  registration time (`WebhookRegistryService.create`/`.update`) _and_
  delivery time (`WebhookDeliveryService.attemptDelivery`, immediately
  before signing/POSTing) — the harder, DNS-rebinding-closing case Section
  51 explicitly asks for.

**`SSRF_ALLOWED_HOSTS`** (`src/common/ssrf/ssrf.config.ts`): a real,
deliberate, narrow exception — an explicit, operator-controlled
exact-hostname allow-list (never a range/wildcard) that skips the
range check entirely for a named hostname, checked before any DNS lookup.
This exists because of a genuine, unavoidable tension: this product's
entire purpose is integrating with a tenant's _own_ on-prem SIEM/EDR/IAM
tools, which legitimately live on private network addresses — a blanket,
unconditional rejection of all private-range targets would make the Tool
Gateway's real purpose impossible, not just "safer." **Loopback and the
metadata range are never exemptable through this list under any
circumstance** — `SSRF_ALLOWED_HOSTS` only ever widens which _hostnames_
skip the check, never which IP ranges are considered generically safe. A
real deployment should leave this unset (full strict enforcement) or list
only its own genuinely-needed internal hostnames; this repo's own
`.env.example` populates it with `127.0.0.1`/`localhost` purely so this
phase's own local HTTP test fixtures (which necessarily bind to loopback)
and Phase 7a's demo tool container keep working — see that config file's
doc comment for the full reasoning, and `docs/threat-model.md`'s SSRF
section for why this is documented as a known, accepted limitation rather
than treated as solved.

## Webhooks (Section 51)

**Data model** (`prisma/tenant.prisma`, migration `20260819015521_add_webhooks`):

- **`WebhookEndpoint`**: `id`, `url` (SSRF-checked at registration and
  delivery), `secretReference` (a `SecretReferenceDescriptor` — the same
  shape `Tool.credentialReference` uses — pointing at an OpenBao KV v2
  secret this service itself generates and writes; never plaintext in the
  row), `subscribedEventTypes` (`String[]`, validated against Phase 9a's
  real `AUDIT_EVENT_TYPES` catalog), `enabled`, `createdBy`/`createdAt`/`updatedAt`.
- **`WebhookDelivery`**: one row per (endpoint, event) delivery attempt
  history — `id`, `webhookEndpointId`, `eventId`/`eventType`, `status`
  (`PENDING`/`SUCCESS`/`FAILED`), `attempts`, `lastAttemptAt`,
  `responseStatus`. `@@unique([webhookEndpointId, eventId])` is this
  model's own idempotency under Kafka's at-least-once redelivery — mirrors
  `AuditIndexerService`'s "upsert by `eventId`" contract.

**Delivery pipeline**:

1. `WebhookDeliveryConsumerService` (`src/webhooks/webhook-delivery-consumer.service.ts`)
   is a Kafka consumer on Phase 9a's `manar.audit-events` topic, mirroring
   `AuditIndexerService`'s consumer pattern exactly (fresh random consumer
   group per process boot, `fromBeginning: false`). For every consumed
   event, it finds every `enabled` `WebhookEndpoint` whose
   `subscribedEventTypes` includes the event's `eventType`, and for each
   match creates a `WebhookDelivery` row and starts a
   `WebhookDeliveryWorkflow`.
2. `WebhookDeliveryWorkflow` (`src/temporal/workflows/webhook-delivery.workflow.ts`)
   calls the `deliverWebhookAttempt` Activity once; Temporal's own real
   `proxyActivities({ retry: {...} })` policy (exponential backoff, 5s
   initial → 5 minute ceiling, 6 total attempts — the same mechanism
   `ApprovalWorkflow`/`AuditRetentionWorkflow` already use, not a
   hand-rolled backoff loop) retries it on failure. Once every retry is
   exhausted, the workflow's own catch calls `markWebhookDeliveryFailed`
   to reach a genuine terminal `FAILED` state.
3. `WebhookDeliveryService.attemptDelivery` (`src/webhooks/webhook-delivery.service.ts`)
   does the real work per attempt: loads the delivery + endpoint + the
   underlying `AuditEvent`, re-validates the URL (SSRF), resolves the
   secret, signs, POSTs, and records the outcome (`attempts`,
   `lastAttemptAt`, `responseStatus`, `status`) before returning or
   throwing.

**A dedicated Temporal task queue** (`WEBHOOK_DELIVERY_TASK_QUEUE`, default
`manar-webhooks`) — deliberately separate from `TEMPORAL_TASK_QUEUE`
(`ApprovalWorkflow`/`AuditRetentionWorkflow`'s shared queue). Production
still runs one worker process (`src/worker.main.ts` now runs two
`Worker.create()` calls, same connection/activities/bundle, one per
queue) — the separate queue exists specifically because this repo's e2e
suites each spin up their own narrowly-bundled in-process Temporal worker,
several of which only register `ApprovalWorkflow`'s activities; sharing
the default queue would let those workers dequeue (and crash on) a
webhook-delivery task meant for someone else. See
`src/webhooks/webhooks.config.ts`'s doc comment for the full reasoning.

### Signing scheme

Every delivery is signed and carries two headers:

```
Manar-Signature: sha256=<hex HMAC-SHA256(secret, "<timestamp>.<body>")>
Manar-Timestamp: <unix milliseconds the request was signed at>
Manar-Event-Type: <the AuditEvent's eventType>
Manar-Delivery-Id: <the WebhookDelivery.id>
```

Implemented once, in `src/webhooks/webhook-signing.ts`
(`signWebhookRequest`/`verifyWebhookSignature`/`buildSignedMessage`) — the
one place this scheme exists, so sender and any reference receiver
verification can never drift apart.

**Body**: `JSON.stringify({ eventId, eventType, timestamp, correlationId,
actor, data })` — the underlying `AuditEvent`'s own content, re-read from
Postgres at delivery time (not duplicated onto the `WebhookDelivery` row
itself).

**Why the timestamp is signed together with the body, not sent unsigned
alongside it**: an attacker who captured one genuinely-signed delivery
must not be able to replay it later with a freshly forged timestamp —
changing `Manar-Timestamp` without knowing `secret` invalidates the
signature outright.

**Replay-protection window**: a receiver is expected to reject any request
whose `Manar-Timestamp` is more than `WEBHOOK_SIGNATURE_TOLERANCE_MS`
(default 5 minutes, `src/webhooks/webhooks.config.ts`) away from its own
clock — checked _before_ the signature in the reference
`verifyWebhookSignature` implementation (cheaper, and a stale timestamp is
rejected regardless of whether the signature would have verified), but the
signature check is still mandatory even for a recent timestamp.
Constant-time comparison (`crypto.timingSafeEqual`) throughout — never a
plain `===` string comparison, which would leak timing information about
how many leading bytes matched.

**Secret lifecycle**: generated once, at `POST /webhooks` time
(`WebhookRegistryService.create`, 32 random bytes, hex-encoded), written
to OpenBao KV v2 immediately, and returned to the caller in plaintext
**exactly once**, in that same response — there is no endpoint to retrieve
it again, matching common "shown once at creation" secret UX. Every later
response (`GET`/`PATCH`/list) omits it entirely.

### Admin endpoints

`WebhooksController` (`src/webhooks/webhooks.controller.ts`):
`POST/GET/PATCH/DELETE /webhooks(/:id)`, `GET /webhooks/:id/deliveries` —
`JwtAuthGuard`+`RolesGuard`, gated to `SECURITY_ADMIN`/`TENANT_OWNER`, the
exact role-gating convention `KillSwitchesController` (the immediately
prior phase) established.

## Idempotency-Key (Section 8)

`IdempotencyInterceptor` (`src/idempotency/idempotency.interceptor.ts`),
Redis-backed (`IdempotencyStoreService`, `IDEMPOTENCY_KEY_TTL_MS` default
24h), applied per-route (`@UseInterceptors(IdempotencyInterceptor)`) —
never blanket-applied globally, and opt-in via the `Idempotency-Key`
request header (a request with no such header is completely unaffected).

**Applied to** (read from the real controllers, not assumed): `POST /agents`
(agent creation — a genuinely new `Agent` row per call), `POST
/policies/:id/versions/:versionId/publish` (policy publish), all five
`POST /.../kill-switch` **activation** endpoints (not the `/deactivate`
pairs — a replayed deactivation is already a harmless no-op; a replayed
activation would otherwise write a duplicate `kill_switch.activated`
`AuditEvent` on every network retry), and `POST /webhooks` (webhook
registration — the strongest case: a replay would otherwise silently
rotate the signing secret and orphan the old one).

**Deliberately NOT applied to grant redemption**
(`GrantService.validateAndConsumeGrant`, `POST /agent/v1/tools/invoke`
with a `grantToken`) — Phase 8 already made that single-use by its own,
different mechanism (the grant token itself is consumed exactly once);
adding a second idempotency layer on top would be redundant, not
protective.

**Mechanics**: `claim()` is a Redis `SET NX`. First claim → the real
handler runs, its resolved value is cached for the TTL window; a replay
with the same key inside that window returns the cached value **without
re-executing the handler at all**. A concurrent duplicate (claimed, no
cached value yet) is rejected with `409 Conflict`. A handler that throws
**releases** the claim rather than caching the error — a failed attempt
must not permanently block a legitimate retry with the same key. Scoped
per (tenant-or-agent, controller.handler, key) — the same literal key
value from two different tenants is never treated as a collision.

## Data residency enforcement (Section 54)

Phase 2 gave every `Tenant` `allowExternalAi`/`allowOutboundTelemetry`/
`allowCloudStorage` flags (default `false`) — `allowExternalAi` went
completely unchecked until this phase. `AiAdvisoryClient`
(`src/ai-advisory/ai-advisory-client.service.ts`) now consults it before
any call that could reach an external provider:

- `AI_ADVISORY_PROVIDER` (`src/ai-advisory/ai-advisory.config.ts`) is this
  side's own declaration of which provider `manar-ai` is _currently
  configured_ to use (there is no "describe yourself" RPC on the
  `AnalysisService` contract for `manar-api` to introspect this over the
  wire) — only `'anthropic'` counts as external; `'ollama'`/`'vllm'` are
  self-hosted and never gated by this check regardless of the flag.
- `residencyAllows(tenantId, rpcName)` — the gate every one of
  `analyzeRisk`/`analyzePromptInjection`/`analyzeDlp` calls **before**
  the circuit-breaker check and before any RPC is attempted. For an
  external provider, it looks up the tenant's `allowExternalAi` flag
  (`ControlPrismaService`); `false` (or a lookup failure — this **fails
  closed**, never permissive on an error) skips the call entirely.

**Reuses, not invents, Phase 10b's existing fail-safe contract**: a
residency block returns exactly the same `null` "no AI signal available"
outcome every existing caller (`RiskEngine.score`,
`CredentialBrokerService`'s DLP/prompt-injection checkpoints) already
treats identically to a `manar-ai` outage — this is a deliberate reuse,
not a new response shape a caller would need to special-case. A residency
block also does **not** count toward the circuit breaker's
consecutive-failure tally — it's a policy decision, not an outage, and
must never trip an unrelated resilience mechanism.

**Tested at the network level**: `src/ai-advisory/ai-advisory-client.service.spec.ts`'s
"data residency enforcement" suite asserts against the _real_ gRPC fake
server's own received-call counters (`fakeServer.callCounts.analyzeRisk`
etc. staying at `0`) — proving the RPC was never attempted, not merely
that the function happened to return `null` for some unspecified reason.

## Known limitations

- **`SSRF_ALLOWED_HOSTS` is a coarse, hostname-only exception mechanism**,
  not a scoped-per-tenant or scoped-per-endpoint allow-list — any
  configured hostname is exempted for every tenant's `Tool`/`WebhookEndpoint`
  registrations on this deployment. A future phase wanting finer-grained,
  per-tenant internal-target allow-listing would need to extend this.
- **No data classification model** (`DataClassificationRule`, Section 53)
  — explicitly out of scope this phase, per the design spec.
- **No compliance-framework mapping** — explicitly out of scope this
  phase, per the design spec.
- **Idempotency caching stores the resolved response value only, not the
  original HTTP status code** — a replayed request is served through the
  same route's normal status-code path (its own `@HttpCode`/default
  decorator), which happens to already match the original call for every
  endpoint this is applied to (all return the same status on every call),
  but this is a design constraint worth knowing if `IdempotencyInterceptor`
  is applied to a route with response-dependent status codes in the
  future.
