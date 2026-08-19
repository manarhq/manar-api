# Phase 12a: Application Hardening & Webhooks — Design

Status: Approved (autonomous execution)
Scope: `manar-api` only
Depends on: Phase 9a (`AuditService`, event catalog), Phase 7b
(`Tool.baseEndpoint` — the existing SSRF-relevant precedent), the
in-flight Kill Switches phase (not a hard dependency, but touches
similar admin-endpoint territory — if it's already merged when you
start, follow its role-gating conventions for consistency)

## Purpose

Section 96 Phase 12's checklist, several items of which are genuine
gaps (webhooks/Section 51 were never built; SSRF protection was never
formalized even though Phase 7's `Tool.baseEndpoint` has taken it on
faith since Phase 7b; a real data-residency enforcement gap exists — see
below) plus hardening items that got informal, inconsistent treatment
phase-by-phase and need a real, deliberate pass now.

## Rate limiting (Redis-backed, decision #76)

Apply to both the human-facing JWT surface and the mTLS agent-facing
surface. Research current official NestJS rate-limiting (`@nestjs/
throttler` or equivalent) with a Redis store (Redis already exists,
Phase 9b). Scope limits sensibly: per-tenant on human endpoints,
per-agent on `/agent/v1/*` — a single misbehaving agent must not be able
to exhaust a limit shared with every other agent in the tenant.

## Security headers & CORS

`@fastify/helmet` (research current setup for the Fastify adapter
specifically). CORS: no wildcard origin in production (Section 99 — this
is an explicit hard rule), configurable allow-list via typed config.

## SSRF protection

Both existing (`Tool.baseEndpoint`, registered in Phase 7b) and new
(webhook target URLs, below) outbound-URL-accepting inputs need real
SSRF controls: reject private/loopback/link-local/metadata-service IP
ranges (169.254.169.254 etc.) at registration time AND re-validate at
call time (DNS rebinding — a hostname that resolved safely at
registration could resolve to an internal address later; don't trust a
one-time check). Write this as a shared, reusable validator, not
duplicated logic between the tool registry and webhooks.

## Webhooks (Section 51 — not built in any prior phase)

- `WebhookEndpoint` (tenant DB): `id`, `url`, `secret` (via
  `SecretProvider`, never plaintext), `subscribedEventTypes` (array,
  from Phase 9a's real event catalog), `enabled`.
- `WebhookDelivery`: `id`, `webhookEndpointId`, `eventId` (the
  `AuditEvent`/domain event it's delivering), `status`, `attempts`,
  `lastAttemptAt`, `responseStatus` (nullable).
- Delivery: subscribe to Phase 9a's Kafka topic (mirroring
  `AuditIndexerService`'s consumer pattern), filter by each endpoint's
  subscribed types, POST with an HMAC signature header (document the
  scheme — timestamp + body signed, replay-protection window, per
  Section 51). Retry via Temporal (reuse the existing worker process) —
  research Temporal's retry policy configuration rather than hand-
  rolling a backoff loop.
- Apply the SSRF validator to every registered/delivered URL.

## Idempotency

Section 8: mutation endpoints where replay could be dangerous need
idempotency-key support. Identify which existing endpoints actually
qualify (agent creation, policy publish, kill-switch activation, tool
registration — read the real controllers, this list may not be
exhaustive) and add `Idempotency-Key` header support (Redis-backed
dedupe within a documented time window) for those specifically — don't
blanket-apply it to read endpoints or ones that are already naturally
idempotent (e.g. Phase 8 already made grant redemption single-use by
its own design, that's not the same mechanism and doesn't need this).

## Data residency enforcement (Section 54 — a real gap)

Phase 2 gave every `Tenant` `allowExternalAi`/`allowOutboundTelemetry`/
`allowCloudStorage` flags (default `false`, the safe default), but
**nothing ever checks them**. Phase 10b's `AiAdvisoryClient` calls
`manar-ai`, which can be configured to use `AnthropicProvider` (an
external cloud AI call) — if a tenant has `allowExternalAi = false`,
that must not happen. Fix: `AiAdvisoryClient` (or a wrapping check
before it) must consult the requesting tenant's `allowExternalAi` flag;
if `false` AND the currently-configured provider is external
(Anthropic), skip the AI advisory call entirely (same fail-safe "no AI
signal" path Phase 10b already established for outages — reuse it, this
is just a different reason for the same outcome) rather than silently
calling out anyway. Document this clearly since it's easy to regress:
whoever later configures a per-tenant or dynamic provider selection must
know this check exists.

## Testing

- Rate limiting actually triggers (a burst of requests past the
  configured limit gets throttled) on both surfaces, scoped correctly
  (tenant A's traffic doesn't exhaust tenant B's or a different agent's
  limit).
- Security headers present on real responses; CORS rejects a
  non-allow-listed origin.
- SSRF: registering a tool or webhook with a private/loopback/
  metadata-service URL is rejected; a URL that would resolve there via
  DNS rebinding is caught at call time too (simulate this — don't just
  test the registration-time check).
- Webhook: a subscribed event triggers a real signed delivery to a test
  receiver; the signature verifies; an unreachable endpoint retries per
  the configured Temporal policy and eventually records a failed
  `WebhookDelivery`.
- Idempotency: replaying the same mutation with the same key doesn't
  double-execute; a different key does execute again.
- Data residency: a tenant with `allowExternalAi = false` never actually
  reaches `AnthropicProvider` (assert this at the network/mock level, not
  just "the function returned null" which could be true for unrelated
  reasons) even when it otherwise would have called out.
- Existing e2e suites across all prior phases still pass unmodified.

## Docs

`docs/security.md` and `docs/threat-model.md` (Section 87/88) — write
these for real now that most of the architecture exists to threat-model
against; cover at minimum the SSRF surface, webhook signing, and the
data-residency enforcement point.

## Out of scope this phase

- Container/Kubernetes hardening, CI security scanning tooling (Phase
  12b)
- Full compliance-framework mapping (separate, lower-priority item)
- Data classification (`DataClassificationRule`, Section 53) — noted as
  a known limitation if not reached
