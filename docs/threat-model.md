# Threat model

Phase 12a (Sections 87/88). Written now, deliberately, because by this
point the real architecture exists to threat-model against — eleven-plus
prior phases (tenancy, mTLS agent identity, OpenFGA/policy/risk
authorization, Temporal-backed approvals, the tamper-evident audit chain,
the AI advisory pipeline, kill switches) plus this phase's own hardening
pass (`docs/security.md`). This document is a walkthrough of trust
boundaries, assets, and the concrete mitigation already in the codebase
for each credible threat — not a generic checklist copied in before the
system existed to check it against.

## Trust boundaries

```
                          ┌─────────────────────────────┐
  Browser / human   ───▶  │   AppModule (JWT-guarded)    │
  dashboard client        │   human-facing surface       │
                          └──────────────┬───────────────┘
                                         │
                          ┌──────────────┴───────────────┐
  Agent SDK (client   ───▶│  AgentMtlsAppModule (mTLS)    │
  certificate)            │  /agent/v1/* surface          │
                          └──────────────┬───────────────┘
                                         │
                     ┌───────────────────┼───────────────────┐
                     ▼                   ▼                   ▼
              Postgres (control    Redis (rate-limit/    Kafka (audit
              + per-tenant DBs)    idempotency/SSE)       event backbone)
                     │                   │                   │
                     ▼                   ▼                   ▼
              OpenBao (PKI +      OpenSearch (audit    Temporal (approval +
              KV v2 secrets)      projection)          webhook workflows)
                                         │
                                         ▼
                          ┌─────────────────────────────┐
                          │  manar-ai (gRPC, advisory-    │
                          │  only — never authoritative)  │
                          └──────────────┬───────────────┘
                                         │ (only if allowExternalAi)
                                         ▼
                              External AI provider (Anthropic)

  Outbound, admin-configured, per-tenant:
    Tool.baseEndpoint  ──▶  a tenant's own SIEM/EDR/IAM/FIREWALL tool
    WebhookEndpoint.url ──▶  a tenant's own receiver
```

Every boundary crossing above either requires a distinct credential (human
JWT vs. agent mTLS client cert vs. OpenBao token vs. the platform operator
token) or is itself the thing under threat-model here (the two
admin-configured outbound edges, `Tool.baseEndpoint`/`WebhookEndpoint.url`).
See `docs/tenant-isolation.md`, `docs/human-auth.md`, and
`docs/agent-identity.md` for the identity/isolation model those first two
boundaries already establish; this document focuses on what's new or
newly enforced as of this phase.

## Assets

1. **Tenant data confidentiality/integrity** — every tenant's own isolated
   Postgres database, audit chain, and OpenSearch projection.
2. **Credential secrecy** — tool credentials, webhook signing secrets,
   agent private keys, human JWTs — never logged, never returned to a
   caller who shouldn't have them.
3. **Authorization correctness** — the deterministic pipeline
   (`AuthorizationService`/`PolicyEngine`/`RiskEngine`/`KillSwitchService`)
   must never be bypassable or fail open.
4. **Manar's own server-side infrastructure** — the actual attack surface
   SSRF protection exists for: Manar's Postgres/Redis/OpenBao/Kafka/Temporal/
   internal network position, reachable only from _inside_ Manar's own
   deployment, never meant to be dialable by an admin-supplied URL.
5. **Availability** — both the human and agent-facing surfaces, and the
   webhook delivery pipeline's own forward progress.

## Threats and mitigations

### T1 — SSRF via `Tool.baseEndpoint` or `WebhookEndpoint.url`

**Threat**: a malicious or compromised tenant admin (or an admin fooled
into pasting an attacker-supplied URL) registers a `Tool`/`WebhookEndpoint`
pointing at Manar's own internal infrastructure or a cloud metadata
service, using Manar's server as a proxy to reach something the admin
themselves has no direct network path to (the classic SSRF exfiltration
pattern — cloud IAM credentials via `169.254.169.254`, an internal
management API, etc.).

**Mitigation**: `assertSafeOutboundUrl` (`src/common/ssrf/url-safety.ts`,
`docs/security.md`'s SSRF section) — protocol allow-list, real DNS
resolution + range check against loopback/private/link-local/metadata/
multicast, re-validated at the _actual moment of every outbound call_
(never cached), applied to both `Tool.baseEndpoint` (`HttpToolAdapter`/
`McpToolAdapter`) and `WebhookEndpoint.url` (registration **and**
delivery).

**Residual risk / known limitation**: `SSRF_ALLOWED_HOSTS`
(`src/common/ssrf/ssrf.config.ts`) is a real, necessary escape hatch — this
product's actual purpose requires reaching a tenant's _own_ internal
tools, which genuinely live on private addresses, so a blanket private-range
rejection would make the core feature unusable. Any hostname on this list
is fully exempted from the range check for every tenant on the deployment
— it is coarse (not scoped per-tenant or per-target) and entirely
operator-trust-based. Loopback and the metadata range specifically are
architecturally **never** exemptable through it (the exemption is checked
against a fixed hostname string, not a range, so `169.254.169.254` would
have to be listed by that exact literal to be exempted — an operator
error, not a validator bypass — and no real deployment's own `.env` would
plausibly do that). This is the single most consequential trade-off this
phase makes, and it's accepted deliberately rather than silently: a future
phase wanting finer-grained (per-tenant, per-target) internal-address
allow-listing would extend this mechanism, not replace the underlying
range check.

### T2 — DNS rebinding around SSRF protection

**Threat**: a hostname resolves to a public, safe address at registration
time (passing the check), then its DNS is repointed to an internal address
by the time a real delivery/tool-invocation happens.

**Mitigation**: `assertSafeOutboundUrl` is deliberately never cached and
is called fresh at the actual moment of every outbound call, not just once
at registration — see `docs/security.md`'s SSRF section for the exact call
sites. Proven with a dependency-injected DNS resolver
(`src/common/ssrf/url-safety.spec.ts`'s dedicated rebinding test: the same
URL resolves safely on the first, registration-time-equivalent call and
unsafely on a second, call-time-equivalent call against the identical
validator invocation) — a deterministic, repeatable simulation rather than
relying on real DNS infrastructure, which can't be reliably staged in a
test environment.

### T3 — Webhook delivery forgery / tampering in transit

**Threat**: an attacker who can reach a tenant's webhook receiver (e.g. on
a shared network, or via a compromised intermediate proxy) sends a forged
event to it, or tampers with a legitimate delivery's body in flight,
attempting to make the receiver believe a fabricated Manar event occurred.

**Mitigation**: every delivery is HMAC-SHA256 signed over `timestamp +
body` (`docs/security.md`'s signing-scheme section,
`src/webhooks/webhook-signing.ts`), with the secret known only to Manar and
the registering tenant (generated server-side, shown once, stored in
OpenBao thereafter). A receiver that verifies the signature can trust both
the sender's identity (only Manar and the tenant know the secret) and the
body's integrity (any tamper invalidates the signature).

### T4 — Webhook delivery replay

**Threat**: an attacker captures one genuinely-signed delivery (e.g. from
an insufficiently secured receiver-side log) and resends it later,
attempting to make the receiver re-process an event that already happened.

**Mitigation**: the timestamp is signed _together with_ the body (not sent
unsigned alongside a signature that only covers the body) — a replayed
request's timestamp is necessarily stale relative to the replay time, and
a receiver following the documented scheme rejects anything outside
`WEBHOOK_SIGNATURE_TOLERANCE_MS` (default 5 minutes) regardless of whether
the signature itself is genuine. Proven directly: `webhook-signing.spec.ts`'s
"rejects a replayed request" test captures a real signed payload and
resends it an hour later, confirming rejection.

### T5 — Webhook secret exposure

**Threat**: the webhook signing secret leaks (logs, database dump, a
compromised admin session reading it back later), letting an attacker
forge deliveries indefinitely.

**Mitigation**: generated once at creation, written to OpenBao KV v2
immediately, returned to the caller in plaintext exactly once (the
creation response) — no endpoint ever returns it again, and the
`WebhookEndpoint.secretReference` column stores only an OpenBao path
pointer, never the value itself. Rotation currently requires deleting and
re-registering the endpoint (no in-place rotation endpoint this phase —
noted here rather than silently absent).

### T6 — Unbounded request volume (DoS) on either public surface

**Threat**: a single tenant's traffic, or a single misbehaving/compromised
agent, exhausts server or downstream (Postgres/OpenFGA/manar-ai) capacity
shared with every other tenant/agent.

**Mitigation**: Redis-backed rate limiting, scoped per-tenant (human
surface) and per-agent (mTLS surface) — see `docs/security.md`'s rate
limiting section. Scoping is the actual security property here, not the
existence of a limit alone: `test/app-hardening-webhooks.e2e-spec.ts`'s
scoping tests specifically prove tenant A's exhausted bucket doesn't
affect tenant B, and one agent's exhausted bucket doesn't affect another
agent in the same tenant.

**Residual risk**: this is per-process-graph rate limiting keyed by
tenant/agent identity, not a network-edge DDoS mitigation (no IP-reputation
or volumetric-attack layer) — out of scope for an application-level
control, expected to sit behind a real edge/CDN layer in production
(Phase 12b's container/infra scope, not this phase's).

### T7 — Cross-origin credential theft via a malicious web page

**Threat**: a malicious website, visited by a user with an active Manar
session, issues cross-origin requests hoping the browser attaches
ambient credentials and a permissive CORS policy lets it read the
response.

**Mitigation**: `resolveCorsOrigin`'s hard production rule — no wildcard
origin, ever, in `NODE_ENV=production` (the process refuses to boot
otherwise) — see `docs/security.md`'s CORS section.
`test/app-hardening-webhooks.e2e-spec.ts` proves a non-allow-listed
`Origin` header gets no `Access-Control-Allow-Origin` response header at
all (real Fastify CORS behavior, not just the pure resolver function in
isolation).

### T8 — Clickjacking / MIME-sniffing / other response-header-level attacks

**Threat**: a malicious page frames a Manar-served response, or a browser
MIME-sniffs a response body into an unintended, more dangerous content
type.

**Mitigation**: `@fastify/helmet` on both applications —
`X-Content-Type-Options: nosniff`, `X-Frame-Options`, and a restrictive
default CSP (`default-src 'none'`, appropriate for a JSON API with no
page-serving surface). Proven present on real responses from both
applications, not merely configured
(`test/app-hardening-webhooks.e2e-spec.ts`).

### T9 — Duplicate side effects from a retried mutating request

**Threat**: a client retries a mutation (network timeout, ambiguous
response, naive client-side retry logic) and the server executes it twice
— a second `Agent` row, a second published `PolicyVersion`, a rotated
webhook secret the original caller doesn't have, a duplicate
`kill_switch.activated` audit trail entry.

**Mitigation**: `Idempotency-Key` support on the specific mutation
endpoints where this is a real risk — see `docs/security.md`'s
idempotency section for exactly which and why. Deliberately not applied
to grant redemption (Phase 8 already has its own, different single-use
mechanism there) or to naturally-idempotent/read endpoints.

### T10 — A tenant's data leaving Manar's infrastructure without consent

**Threat**: a tenant with `allowExternalAi = false` (the residency-restricted,
safe default) has action/risk/DLP content sent to an external cloud AI
provider anyway, because nothing ever checked the flag (the actual,
previously-real gap this phase closes — Section 54).

**Mitigation**: `AiAdvisoryClient.residencyAllows` — see
`docs/security.md`'s data residency section for the full mechanism.
**Fails closed**: a control-DB lookup failure is treated as "not allowed,"
never as permissive-by-default. Proven at the network/transport level
(`src/ai-advisory/ai-advisory-client.service.spec.ts`'s residency suite
asserts the real fake gRPC server's own received-call counters stay at
zero), not merely that the wrapping function happened to return `null`.

**Residual risk / known limitation**: this check only gates
`AiAdvisoryClient`'s own calls — `allowOutboundTelemetry`/`allowCloudStorage`
(the other two Phase 2 residency flags) remain unenforced anywhere in the
codebase, exactly as before this phase (no telemetry-emitting or
cloud-storage-writing code path exists yet to enforce them against) —
noted explicitly here rather than left to look like this phase closed the
whole residency story.

### T11 — Authorization/kill-switch bypass (recap, not re-litigated here)

Already covered in full by `docs/authorization-model.md`,
`docs/policy-model.md`, and `docs/kill-switches.md` — this phase adds no
new authorization logic, only hardening around the edges (rate limiting,
SSRF, webhooks) that sits _outside_ that pipeline. Included here only to
be explicit that this document isn't silently narrowing the threat model
to "whatever Phase 12a touched."

## Out of scope (explicit, per the design spec)

- **Data classification** (`DataClassificationRule`, Section 53) — no
  classification model exists; nothing in this phase tags data by
  sensitivity level.
- **Compliance-framework mapping** (SOC 2 / ISO 27001 / etc. control
  cross-referencing) — a separate, lower-priority effort.
- **Network-edge DDoS/volumetric protection** — see T6's residual risk.
- **Container/Kubernetes/CI security hardening** — Phase 12b's scope, a
  parallel workstream, not duplicated here.
