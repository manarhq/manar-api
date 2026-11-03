# Agent identity & enrollment

This is `manar-api`'s implementation of Phase 4 (Agent Identity &
Enrollment): `docs/superpowers/specs/2026-08-18-phase4-agent-identity-design.md`.
It gives agents independent security-principal status — workload identity
based on asymmetric crypto + X.509 certificates, never a shared
secret/API key — with OpenBao as the PKI _signing_ backend and Manar
owning every policy decision around who gets a certificate and what it's
allowed to say.

## Local infra: OpenBao

`deploy/docker-compose.yml` adds an `openbao` service
(`openbao/openbao:2.6.1`, file storage on a named volume, initialized once and
unsealed on every start by `deploy/openbao-entrypoint.sh`; local dev only, CI
uses `-dev` mode). Unlike Postgres/Keycloak, a fresh volume boots with **no
PKI configured** — run `pnpm infra:openbao-init`
(`deploy/openbao-init.mjs`) once the container is healthy. That script
drives OpenBao's HTTP API directly (no `vault`/`bao` CLI dependency, so it
runs identically in GitLab CI) to:

1. Enable the PKI secrets engine at `pki` (root) and `pki_int`
   (intermediate).
2. Generate an ECDSA P-256 root CA (`pki/root/generate/internal`) — current
   guidance favors P-256/P-384 over RSA-2048 for new workload-identity PKI
   (smaller, faster, comparable-or-stronger security per bit).
3. Generate an intermediate CA CSR, sign it with the root
   (`pki/root/sign-intermediate`), and mount the signed cert as the online
   issuer (`pki_int/intermediate/set-signed`). The root is never used for
   issuance again after this — standard PKI practice, avoids an
   always-online root.
4. Create `manar-agent`, the role `CertificateAuthorityService` calls via
   `sign-verbatim` for agent leaf certificates (24h TTL — see that
   service's `AGENT_LEAF_CERTIFICATE_TTL`).
5. Create `manar-server` and issue a TLS server certificate/key for the
   API's own `/agent/v1/*` mTLS listener.

The script is idempotent: `root/generate/internal` and
`intermediate/generate/internal` are **not** idempotent by themselves
(calling either again silently replaces the CA/key, invalidating every
certificate signed under the old one) — the script guards this with an
existence check (`GET .../ca/pem`) before generating either.

Writes `deploy/openbao/{root-ca,intermediate-ca,ca-chain,server-cert,server-key}.pem`
(gitignored — regenerable, and the CA's own private key never leaves
OpenBao; only the server listener's key is ever written to disk, and only
because that's a TLS server identity, not an agent's).

## Data model (tenant DB)

- **`Agent`** — `slug`, `identifier` (`agent://<tenantSlug>/<slug>`,
  unique — this agent's SPIFFE-like workload identity URI), `displayName`,
  `status` (`PENDING_ENROLLMENT | ACTIVE | REVOKED | KILLED` —
  `KILLED` is reserved for a later, dedicated kill-switch phase, not set by
  anything here), `capabilities` (`Json`, unused until Phase 5+),
  `createdBy` (FK to `UserProfile`).
- **`AgentGroup`** + **`AgentGroupMembership`** — membership only, no
  group-based policy yet (Phase 5+).
- **`AgentEnrollmentToken`** — `tokenHash` (never the raw token — see
  "Enrollment tokens" below), `expiresAt` (15 minutes), `usedAt`
  (single-use).
- **`AgentCertificate`** — issued-certificate metadata: `serialNumber`
  (canonical form: uppercase hex, no separators — see
  `src/agents/serial-number.util.ts`), `subject`, `notBefore`/`notAfter`,
  `revokedAt`/`revocationReason`. Never the private key (never exists
  server-side) or the full certificate PEM (OpenBao is the system of
  record for the certificate material itself).

Migration: `prisma/tenant/migrations/20260818184037_add_agent_identity_and_enrollment`.

## `CertificateAuthorityService`: Manar owns policy, OpenBao only signs

`src/agents/certificate-authority.service.ts`, per Section 16 of the
master prompt:

1. **Validates the CSR's Subject Alternative Name** against the enrolling
   agent's expected `agent://<tenantSlug>/<slug>` identifier — and its
   self-signature (proof the requester holds the matching private key).
   This runs entirely inside this service, _before_ OpenBao is ever
   called, and is the actual security boundary: OpenBao's `sign-verbatim`
   signs _exactly_ whatever subject/SAN a CSR contains, with no
   name-constraint enforcement of its own by design (that's what
   "verbatim" means) — trusting it to reject a mismatched CSR would be
   trusting a system that was never asked to check in the first place.
   Because the subject is copied verbatim too, it is pinned: exactly one
   attribute, `CN=<agent:// identifier>` (hosts may also send their bare
   machine id, unless it looks like a service name such as `manar-*`). No
   other SAN, no other attribute.
2. Enforces a **24-hour leaf-certificate TTL**
   (`AGENT_LEAF_CERTIFICATE_TTL`) — short-lived by design, so a
   certificate compromised outside Manar's own revocation path
   self-expires quickly. Certificate auto-renewal before expiry is out of
   scope this phase (a later SDK responsibility).
3. Calls OpenBao's `sign-verbatim` (`OpenBaoPkiClient`) against the
   intermediate's `manar-agent` role.
4. Persists the issued certificate's metadata to `AgentCertificate`.
5. `revoke(tenantClient, agentId, reason)` calls OpenBao's revoke
   endpoint for every currently-unrevoked certificate, then marks them
   revoked locally and sets `Agent.status = REVOKED`.

CSR parsing/generation uses `@peculiar/x509` (WebCrypto-based, actively
maintained) — Node has no built-in CSR (PKCS#10) parsing API.

## Enrollment flow (Section 14)

1. `POST /agents` (`SECURITY_ADMIN`/`TENANT_OWNER`, `JwtAuthGuard`+`RolesGuard`)
   → creates an `Agent` in `PENDING_ENROLLMENT`.
2. `POST /agents/:id/enrollment-tokens` → generates a token, stores only
   its hash, returns the raw token **once**.
3. The SDK (`packages/sdk-node`) generates a keypair + CSR locally and
   calls `POST /agents/enroll` with `{ token, csr }`.
4. Server looks the token up by hash, checks not expired/not used,
   validates the CSR via `CertificateAuthorityService`, issues the
   certificate, marks the token used, sets `Agent.status = ACTIVE`,
   returns the certificate + CA chain.
5. A second attempt with the same token fails, even if it somehow leaked.

### Enrollment tokens: hashing and tenant/agent resolution

`src/agents/enrollment-token.util.ts`. Tokens are 256 bits of
`crypto.randomBytes`, hashed at rest with plain SHA-256 — unlike password
hashing, there's no offline-guessability concern a slow KDF would defend
against, since brute-forcing 256 bits of true randomness is infeasible
regardless of hash speed (the same reasoning API-key/webhook-secret
schemes like Stripe's or GitHub's use).

**Design decision not fully pinned by the spec:** `POST /agents/enroll` is
deliberately unauthenticated (an enrolling agent has no JWT/issuer), but
still has to resolve _which tenant's isolated database_ to look the token
up in — and the SDK has to build a CSR whose SAN already matches what the
server expects _before_ any network call, using only the single `token`
argument the spec's `enroll(token)` shape documents. Both problems are
solved by giving the token format a plaintext, self-describing prefix:
`<tenantSlug>:<agentSlug>:<secret>`. Neither slug is a secret, and the
_whole_ raw token (prefix included) is what gets hashed, so tampering with
either slug after the fact invalidates the hash lookup too. `packages/sdk-node/src/enrollment-token.ts`
mirrors this format (deliberately duplicated, not imported from
`manar-api`'s source — the SDK depends only on the wire format both sides
agree on, not on the server application).

## mTLS agent authentication

`src/agent-mtls/` is a **second, wholly separate NestJS application**
(`AgentMtlsAppModule`), bootstrapped alongside the human-facing app in
`src/main.ts` on its own HTTPS port (`AGENT_MTLS_PORT`, default 3443).
This is structural, not incidental: Fastify/Node's `https` server options
(`requestCert`/`rejectUnauthorized`/`ca`) are per-listener, so the
mandatory client-cert mTLS posture here can never bleed into the
human-facing HTTP listener (`AppModule`, `PORT`) or vice versa. Each
`NestFactory.create()` call gets its own DI container, so `@Global()`
modules like `DatabaseModule` are imported explicitly into
`AgentMtlsAppModule` too — "global" only means global within one
application's module graph.

`AgentMtlsGuard` (`src/agent-mtls/agent-mtls.guard.ts`) resolves a
verified client certificate's SAN (`agent://<tenantSlug>/<slug>`) back to
a tenant database (mirroring how `JwtAuthGuard` resolves tenant identity
from a verified token's issuer, never a client-supplied value), then an
`Agent` + `AgentCertificate` row, and rejects unless the agent is `ACTIVE`
**and** that specific certificate serial isn't individually revoked —
defense in depth beyond the TLS layer's own chain validation, since a
certificate can be revoked before its `notAfter`. `GET /agent/v1/whoami`
is a trivial guarded endpoint proving this works end-to-end; it's test
infrastructure for this phase, not scope creep — Phase 5+ adds real
endpoints under this prefix.

### A real bug this phase's tests caught: the `ca` trust store needs the full chain

`AGENT_MTLS_CLIENT_CA_PATH` must point at the **full chain**
(`ca-chain.pem`: intermediate + root), not the intermediate alone. Node's
`tls`/`https` `ca` option does not treat a listed certificate as an
implicit trust anchor the way OpenSSL's CLI `-partial_chain` flag does:
verifying a client certificate issued by the intermediate requires the
intermediate's _own_ issuer (the root) to also be present in the trust
store, or verification fails closed with `UNABLE_TO_GET_ISSUER_CERT` —
which, with `rejectUnauthorized: true`, surfaces as a bare "socket hang
up"/`ECONNRESET` with no application code ever reached (confirmed against
a bare `node:https` server, independent of Fastify/Nest, while diagnosing
the agent-identity e2e suite's first failing run). `deploy/openbao-init.mjs`
already writes `ca-chain.pem` for exactly this reason.

## Revocation

`POST /agents/:id/revoke` (human-triggered; the design spec notes a later
kill-switch phase reuses this) → `CertificateAuthorityService.revoke`. A
revoked agent's certificate stops working on its _next_ request, not
merely at next renewal — verified by an actual test
(`test/agent-identity.e2e-spec.ts`'s "immediate revocation" scenario:
provision, use successfully once via `/agent/v1/whoami`, revoke, retry,
must fail), per Section 71's mandatory invariant.

`REVOKED` and `KILLED` are terminal. `POST /agents/:id/enrollment-tokens`
returns 409 for such an agent, and `POST /agents/enroll` refuses a token
issued before the revocation (uniform 401, audited as
`agent.enrollment_failed` with reason `agent_terminated`) before OpenBao
signs anything.

## TypeScript SDK (`packages/sdk-node`)

A new pnpm workspace package (`pnpm-workspace.yaml`'s `packages: ['packages/*']`),
kept in this repo rather than a fourth git repo — it's tightly coupled to
`manar-api`'s enrollment API surface, and there's no concrete technical
requirement for separation yet.

```ts
const manar = new ManarAgent({ endpoint, identityStore });
await manar.enroll(enrollmentToken);
```

- `IdentityStore` is an interface (`save`/`load`/`clear`) shaped broadly
  enough for a Linux keyring/macOS Keychain/TPM/Kubernetes
  Secret/HSM-backed implementation later without any caller changing —
  this phase ships one concrete implementation, `FileIdentityStore`: the
  private key is never written to disk in plaintext, encrypted with
  AES-256-GCM (authenticated; a 96-bit nonce per current guidance, _not_
  128-bit) under a key derived via scrypt (`N=2^17, r=8, p=1` — OWASP's
  current recommended cost parameters, stronger than Node's historical
  default since this only runs at enroll-time, not a hot path), written
  atomically (temp file + rename, mode `0600`). The passphrase itself is
  never read from the environment by the SDK — the caller decides where
  it comes from, keeping the SDK a plain library with no implicit env
  coupling.
- `generateAgentCsr` generates an ECDSA P-256 keypair and CSR locally
  (`@peculiar/x509` + Node's `crypto.webcrypto`) — the private key never
  leaves the process or gets transmitted; only the CSR (carrying the
  public key half) does.
- No task/execute API yet (Section 68's full ergonomics arrive with the
  phases that add those server capabilities).

**Note for consumers:** `@peculiar/x509` depends on `tsyringe`, which
requires a `Reflect` polyfill. `manar-api`'s own app gets this for free
(NestJS always loads `reflect-metadata` as part of its own bootstrap), but
a real agent process using this SDK standalone has no NestJS anywhere in
it — the SDK package imports `reflect-metadata` itself
(`packages/sdk-node/src/csr.ts`) so consumers don't need to remember to.

## Testing

`test/agent-identity.e2e-spec.ts` runs every mandatory scenario from the
design spec's "Testing" section against a real HTTP server, real local
Postgres, real local Keycloak (for the human operator's JWT), and real
local OpenBao (`pnpm infra:up` + `pnpm infra:openbao-init`) — nothing
mocks the CA or the database:

1. Full enrollment flow end-to-end via the actual SDK hitting the actual
   API and actual OpenBao.
2. Reusing an already-used enrollment token fails.
3. An expired enrollment token fails — the token TTL is a fixed constant
   (15 minutes), not configurable per-environment the way Keycloak's
   realm `accessTokenLifespan` is (Phase 3's approach), so this test
   backdates the real, persisted token row's `expiresAt` via the real
   tenant database directly, rather than waiting 15 real minutes.
4. A CSR whose SAN doesn't match the enrolling agent is rejected (400).
5. Immediate revocation (provision → use successfully once → revoke →
   retry must fail).
6. An mTLS request with a certificate from a foreign (non-Manar) CA is
   rejected — the TLS handshake itself fails, since the trust anchor is
   only ever the real Manar intermediate/root, regardless of what agent
   identity a foreign certificate's SAN claims.
7. The private key never appears in any captured log line or outbound
   request body — asserted by actually spying on `process.stdout.write`
   and `globalThis.fetch` for the duration of the test and grepping the
   captured output, not by inspection.

CI (`.gitlab-ci.yml`'s `test:e2e` job) adds `openbao/openbao:2.6.1` as a
third service alongside Postgres/Keycloak, polls its `sys/health` endpoint
(no Docker healthcheck support in GitLab CI services, same limitation
Phase 3's Keycloak wait-loop already works around), runs
`pnpm infra:openbao-init` against it, and builds `packages/sdk-node`
before `pnpm test:e2e` (the suite imports the real `@manar/sdk-node`
package, which needs its compiled `dist/` to resolve).

## Out of scope this phase

- Agent capabilities/task scoping (Phase 5).
- Certificate auto-renewal.
- Kill switches beyond direct per-agent revocation (Phase 5+/a dedicated
  kill-switch phase per Section 32).
- Python SDK (Section 69 — arrives with `manar-ai`'s own relevant phase).
- Hardware-backed key storage adapters beyond the `IdentityStore`
  interface.
- A production-grade OpenBao auth method for `OpenBaoPkiClient`
  (`OPENBAO_TOKEN` is a deployment-wide bootstrap token, analogous to
  `KeycloakAdminClient`'s bootstrap-admin pattern — a real deployment
  would scope this to a narrow OpenBao policy via AppRole/Kubernetes auth
  instead of a static root token).
