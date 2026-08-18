# Phase 4: Agent Identity & Enrollment — Design

Status: Approved (autonomous execution)
Scope: `manar-api` (agent domain + CA orchestration + mTLS) and a new
`packages/sdk-node` workspace package within `manar-api` (the TypeScript
agent SDK — kept in this repo's pnpm workspace rather than a fourth git
repo, per the standing "don't create repos without a concrete technical
requirement" rule; it's tightly coupled to manar-api's enrollment API
surface).
Depends on: Phase 2 (tenant DB), Phase 3 (tenant/auth context — agent
enrollment is initiated by an authenticated human)

## Purpose

Implement Sections 13-17: agents as independent security principals with
workload identity based on asymmetric crypto + X.509 certs, one-time
enrollment where the private key never leaves the agent, and OpenBao as
the PKI backend (Manar owns enrollment policy, not raw cert signing).

## Local infra addition

Add OpenBao to `deploy/docker-compose.yml`. Dev-mode init: enable the PKI
secrets engine, generate a root CA, generate an intermediate CA signed by
root, mount the intermediate as the online issuing CA (root stays
offline/unused for issuance — standard PKI practice, avoids an
always-online root). Research OpenBao's current official PKI setup docs
for the exact API calls — don't guess the endpoint/policy shape.

## Data model (tenant DB)

- `Agent`: `id`, `slug`, `identifier` (`agent://<tenantSlug>/<slug>`,
  unique), `displayName`, `status` (enum: `PENDING_ENROLLMENT | ACTIVE |
REVOKED | KILLED`), `capabilities` (Json, unused until Phase 5+, kept
  minimal), `createdAt`, `createdBy` (FK to `UserProfile`).
- `AgentGroup`: `id`, `name` — membership is a join table. Minimal this
  phase (no group-based policy yet, that's Phase 5+).
- `AgentEnrollmentToken`: `id`, `agentId` (FK), `tokenHash` (never store
  the raw token — hash at rest per Section 14), `expiresAt` (short — e.g.
  15 minutes), `usedAt` (nullable — single-use), `createdBy`.
- `AgentCertificate`: `id`, `agentId` (FK), `serialNumber`, `subject`,
  `notBefore`, `notAfter`, `revokedAt` (nullable), `revocationReason`
  (nullable).

## `CertificateAuthorityService`

Manar-owned responsibilities per Section 16 — OpenBao only signs:

- Validates the CSR's subject/SAN matches the agent's expected identifier
  (reject CSRs requesting a subject that doesn't match the enrolling
  agent — this is the actual security boundary, not OpenBao's).
- Enforces TTL policy (short-lived leaf certs — pick and document a
  concrete value, e.g. 24h, with the SDK responsible for renewal before
  expiry in a later phase; renewal automation itself is out of scope this
  phase).
- Calls OpenBao's PKI `sign-verbatim` (or the appropriate current
  endpoint — verify in docs) against the intermediate CA role scoped to
  this tenant.
- Persists the issued cert's metadata to `AgentCertificate`.
- `revoke(agentId, reason)`: calls OpenBao's revoke endpoint, updates
  `AgentCertificate.revokedAt`, sets `Agent.status = REVOKED`.

## Enrollment flow (Section 14)

1. Authenticated human (`RequireRole` a role capable of managing agents —
   reuse Phase 3's guard) calls `POST /agents` → creates `Agent` in
   `PENDING_ENROLLMENT`.
2. `POST /agents/:id/enrollment-tokens` → generates a random token,
   stores only its hash, returns the raw token once (never retrievable
   again).
3. SDK-side (see below): generates an ECDSA or RSA keypair locally
   (research current recommended algorithm/curve for X.509 workload
   identity — don't default to something outdated), builds a CSR with
   the expected subject, calls `POST /agents/enroll` with
   `{ token, csr }`.
4. Server: looks up the token by hash, checks not expired/not used,
   validates the CSR against `CertificateAuthorityService`, issues the
   cert, marks token used, sets `Agent.status = ACTIVE`, returns the
   signed certificate (and CA chain) to the SDK.
5. Enrollment is one-shot: a second attempt with the same token fails
   (already used) even if it somehow leaked.

## mTLS agent authentication

Agent-facing endpoints (a distinct router prefix, e.g. `/agent/v1/*`,
separate from the human-facing `/api/v1/*` Phase 3 guarded surface)
require client-certificate mTLS. Fastify/Node's TLS server verifies the
client cert chains to the intermediate CA; a guard extracts the verified
cert's subject/SAN, resolves it back to an `Agent` row, checks
`status === 'ACTIVE'` and the specific `AgentCertificate.serialNumber`
isn't revoked (defense in depth beyond the TLS layer's own chain
validation — a cert can be individually revoked before its `notAfter`).
Reject if the resolved agent's status is anything but `ACTIVE` — this is
the enforcement point Phase 4's revocation test (below) verifies.

## Revocation

`POST /agents/:id/revoke` (human-triggered, later reused by the kill
switch in Phase 5+) → `CertificateAuthorityService.revoke`. A revoked
agent's certificate must stop working on its _next_ request, not merely
at next renewal — verified by an actual test, not assumed.

## TypeScript SDK (`packages/sdk-node`)

Minimal this phase (Section 68's full ergonomics — task fetch, execute,
delegate — arrive with the phases that add those server capabilities):

```ts
const manar = new ManarAgent({ endpoint, identityStore });
await manar.enroll(enrollmentToken);
```

- `identityStore` abstraction (Section 15) with one concrete
  implementation this phase: an encrypted-file keystore (the private key
  never gets written in plaintext to disk). Define the interface broadly
  enough that Linux keyring/macOS Keychain/TPM/K8s-Secret/HSM adapters can
  be added later without changing callers — but only implement the file
  adapter now.
- `enroll()` generates the keypair+CSR locally (key never transmitted),
  calls the enrollment endpoint, stores the returned cert alongside the
  key via `identityStore`.
- No task/execute API yet — those need Phase 5's task model to mean
  anything.

## Testing

- Full enrollment flow end-to-end (SDK → real local API → real local
  OpenBao): token issued, CSR submitted, cert returned, agent now
  `ACTIVE`, SDK's `identityStore` holds a usable cert+key.
- Reusing an already-used enrollment token fails.
- Expired enrollment token fails.
- A CSR whose subject doesn't match the enrolling agent's expected
  identifier is rejected (proves Manar validates the CSR, not just trusts
  whatever OpenBao would sign).
- An mTLS request with a valid-but-revoked agent certificate is rejected
  immediately (this is Section 71's mandatory immediate-revocation
  invariant test — provision, use successfully once, revoke, retry, must
  fail).
- An mTLS request with a cert from a different tenant's issuing CA is
  rejected (cross-tenant agent identity cannot be used).
- Private key is never present in any request body, log line, or stored
  server-side anywhere — assert this explicitly (grep captured
  logs/request bodies in the test, don't just assume).

## Out of scope this phase

- Agent capabilities/task scoping (Phase 5)
- Certificate auto-renewal
- Kill switches beyond direct per-agent revocation (Phase 5+/dedicated
  kill-switch phase per Section 32)
- Python SDK (Section 69 — arrives with `manar-ai`'s own relevant phase)
- Hardware-backed key storage adapters beyond the interface
