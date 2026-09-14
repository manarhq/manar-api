# Release integration matrix — 2026-11-11

Built from source, runtime configuration, UI labels, docs, demo definitions
and deployment charts across all three repositories, per brief §7.

"All integrations" here means **every integration currently implemented,
documented, exposed or advertised by these repositories, plus every
connector added by this release.** It is not a claim that a generic adapter
supports every vendor, and no integration has been dropped from the list to
make the gate easier.

Status vocabulary, used strictly:

| Status              | Meaning                                                                                                                                                    |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **VERIFIED**        | Exercised against its actual service in this environment, with the evidence named.                                                                         |
| **DEMO-FIXTURE**    | Works, and is exercised, against a fixture this project ships. Real regression value; **not** evidence about any vendor.                                   |
| **BLOCKED**         | The protocol/connector work exists, but verification needs access this workspace does not contain. Per brief §7 this is an explicit blocker, never a pass. |
| **NOT-IMPLEMENTED** | Named somewhere but not built. Recorded so it is not mistaken for either of the above.                                                                     |

Last updated: 2026-09-08. Environment: local developer stack
(`pnpm infra:up`), which is **not** production-like — see
`evidence/2026-09-08-gates.md`.

---

## Human identity

| Integration                                                 | Protocol                  | Status              | Evidence / blocker                                                                                                                                                                                             |
| ----------------------------------------------------------- | ------------------------- | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Keycloak OIDC login, logout, token refresh, expiry          | OIDC / OAuth2 + PKCE S256 | **VERIFIED**        | Keycloak 26.7.1 running; `test/auth.e2e-spec.ts` covers login, role enforcement, cross-tenant isolation and **expired-token rejection** (that last case caught a real regression this session).                |
| Per-tenant realm provisioning                               | Keycloak Admin REST       | **VERIFIED**        | `TenantProvisioningService`; exercised by the tenant e2e suites.                                                                                                                                               |
| Role grant/revoke synced to realm role mappings             | Keycloak Admin REST       | **VERIFIED**        | `test/users.e2e-spec.ts`, including the privilege-escalation guard on both grant and revoke.                                                                                                                   |
| Upstream identity federation (customer IdP behind Keycloak) | OIDC/SAML                 | **NOT-IMPLEMENTED** | `manar-web` has an SSO settings page, but no federation is configured or tested. If it is in release scope it must be built and verified; it is currently a settings surface without an integration behind it. |

## Agent identity and SDK

| Integration                                        | Protocol            | Status           | Evidence / blocker                                                                                            |
| -------------------------------------------------- | ------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------- |
| Agent enrollment (CSR → OpenBao PKI signing)       | X.509 / OpenBao PKI | **VERIFIED**     | `pnpm infra:openbao-init` provisions a real root + intermediate CA; `test/agent-identity.e2e-spec.ts`.        |
| mTLS agent surface (port 3443)                     | mTLS                | **VERIFIED**     | Separate Fastify listener with `requestCert`/`rejectUnauthorized`; SAN pinned to the agent's `identifier`.    |
| Certificate revocation checked per request         | —                   | **VERIFIED**     | Per-serial `revokedAt` consulted on every request, not only at handshake.                                     |
| Task delegation with deterministic subset checking | —                   | **VERIFIED**     | `test/task-delegation.e2e-spec.ts`.                                                                           |
| Approval resumption via one-use grant              | HS256 grant token   | **VERIFIED**     | Atomic `UPDATE ... WHERE consumedAt IS NULL`; `test/approvals.e2e-spec.ts` covers the concurrent-decide race. |
| `@manar/sdk-node` agent SDK                        | —                   | **DEMO-FIXTURE** | Builds and typechecks in CI; no published-package or third-party-consumer verification.                       |

## REST / HTTP tools

| Integration                                                                          | Status                           | Evidence / blocker                                                                                                                                                                                                   |
| ------------------------------------------------------------------------------------ | -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Registration, schema/parameter validation, scoped credentials                        | **VERIFIED**                     | `test/tool-gateway.e2e-spec.ts`.                                                                                                                                                                                     |
| Safe execution: SSRF allow-listing, private-IP and metadata blocking                 | **VERIFIED**                     | `src/common/ssrf/url-safety.spec.ts` (37 tests).                                                                                                                                                                     |
| **Redirect-aware egress** (per-hop re-validation, credential stripping cross-origin) | **VERIFIED**                     | Added this release; 6 of the new cases fail against the previous behaviour.                                                                                                                                          |
| Response size limit                                                                  | **VERIFIED**                     | 2 MiB cap, `Content-Length` checked then stream-counted.                                                                                                                                                             |
| Timeouts and unknown outcomes                                                        | **BLOCKED — and a known defect** | Timeouts are bounded, but generic retries still repeat non-idempotent actions and there is no `UNKNOWN` outcome state. See `BLOCKERS.md` B7. This is a release blocker, not a pass.                                  |
| Connection test / health check per tool                                              | **NOT-IMPLEMENTED**              | The console shows `tool.enabled`, which is a flag, not verified connectivity. Brief §7 requires disabled / unconfigured / configured-but-unverified / connected / degraded / expired / failed to be distinguishable. |
| Credential rotation and revocation                                                   | **NOT-IMPLEMENTED**              | Credentials resolve through OpenBao/env references; no rotation workflow exists.                                                                                                                                     |

## MCP tools

| Integration                                                | Status                   | Evidence / blocker                                                                                                                                                                                             |
| ---------------------------------------------------------- | ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Streamable HTTP transport, initialize / discover / invoke  | **DEMO-FIXTURE**         | `test/support/mcp-test-server.ts` — a minimal MCP server written for this project. Proves the adapter architecture; proves nothing about any vendor's MCP server.                                              |
| **Authorization-to-execution parameter binding**           | **VERIFIED**             | Fixed this release: caller `params` could previously overwrite the authorized `resource`. `src/tools/mcp-tool.adapter.spec.ts`. See `BLOCKERS.md` B2.                                                          |
| Bounded connect / initialize / invoke / cleanup lifecycle  | **VERIFIED**             | Fixed this release; previously only the final tool call was bounded, leaving the SDK's 60s `initialize` default in play.                                                                                       |
| MCP descriptions/annotations treated as untrusted metadata | **VERIFIED (by design)** | They are never consulted as a permission or risk authority.                                                                                                                                                    |
| Redirect behaviour of the MCP transport                    | **BLOCKED**              | The MCP SDK's `StreamableHTTPClientTransport` does its own HTTP, so the redirect-aware fetch above does not cover it. Not yet audited.                                                                         |
| Real vendor MCP server, at the versions a customer runs    | **BLOCKED**              | No vendor MCP endpoint or test tenant exists in this workspace. Brief §7 explicitly requires testing actual supported versions rather than assuming newest-spec compatibility — that cannot be done from here. |

## AI providers

| Integration                                          | Status                                     | Evidence / blocker                                                                                                                                                                                                                                                                                                                                                                        |
| ---------------------------------------------------- | ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Ollama (self-hosted)                                 | **BLOCKED**                                | The adapter is real and unit-tested against a mocked transport. `pnpm infra:up:ai` can pull `qwen3:8b` and run genuine local inference, but that has **not** been run in this session. Brief §7 is explicit: a passing deterministic demo or an `available: false` envelope proves degradation behaviour, not working AI.                                                                 |
| vLLM                                                 | **BLOCKED**                                | `app/providers/vllm_provider.py` states outright it has never been exercised against a real vLLM process.                                                                                                                                                                                                                                                                                 |
| Anthropic                                            | **BLOCKED**                                | No API key in this workspace, and pointing one at a real endpoint would be an external egress of customer-shaped data — out of scope without explicit authorization.                                                                                                                                                                                                                      |
| Structured (schema-forced) output                    | **VERIFIED**                               | Enforced at the provider layer with `additionalProperties: false` hardening and `extra="forbid"` contracts; 22 provider tests.                                                                                                                                                                                                                                                            |
| Fail-secure behaviour when a provider is unavailable | **VERIFIED**                               | Independent hot/long-form circuit breakers; zero-confidence fail-secure results; `test/ai-advisory.e2e-spec.ts` and `test/phase10c-ai-extended.e2e-spec.ts` both run with manar-ai unreachable.                                                                                                                                                                                           |
| **Egress redaction before an external model call**   | **VERIFIED**                               | Added this release. Deterministic redaction runs before the prompt is built, the redacted text is re-scanned, and the provider call is abandoned if anything still matches. Cost measured, not asserted: 338/1112 characters withheld on a secret-dense corpus, 11 deterministic findings before and after, 0 residual matches.                                                           |
| **mTLS + peer identity on the API↔AI channel**       | **VERIFIED (server), CONFIGURED (client)** | manar-ai binds `require_client_auth=True` with a peer-identity allow-list and refuses plaintext under staging/production; tests use real openssl-issued certificates over real sockets. The manar-api client gained `AI_ADVISORY_TLS_*` config this release, defaulting off so the plaintext developer stack still works. **The two have not yet been run against each other over mTLS.** |

## Event and evidence pipeline

| Dependency                                  | Status              | Evidence / blocker                                                                                                                                                                                                                                    |
| ------------------------------------------- | ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| PostgreSQL (control + per-tenant databases) | **VERIFIED**        | 17 tenant migrations applied to a clean database with no drift; database-per-tenant isolation.                                                                                                                                                        |
| OpenFGA                                     | **VERIFIED**        | v1.18.3 running; authorization e2e suites pass.                                                                                                                                                                                                       |
| OpenBao (PKI + KV)                          | **VERIFIED**        | Real root/intermediate CA issued during this session.                                                                                                                                                                                                 |
| Redis                                       | **VERIFIED**        | Rate limiting, idempotency store and SSE pub/sub; a storage outage now fails open on rate limiting only, with the reasoning recorded.                                                                                                                 |
| Kafka                                       | **PARTIAL**         | Publishes and is consumed, but publication is fire-and-forget with no outbox — a broker outage silently drops events with no backfill. `BLOCKERS.md` B15.                                                                                             |
| OpenSearch                                  | **VERIFIED**        | Indexing, search and reindex-from-Postgres all exercised. Note the environment caveat: the host disk crossed OpenSearch's flood-stage watermark mid-session and the index went read-only, which produced six misleading e2e failures until diagnosed. |
| Temporal                                    | **VERIFIED**        | Approval, retention and webhook-delivery workflows all exercised.                                                                                                                                                                                     |
| Evidence export (signed bundle)             | **VERIFIED**        | `test/evidence-export.e2e-spec.ts`.                                                                                                                                                                                                                   |
| Retention / archival before pruning         | **NOT-IMPLEMENTED** | Pruning exists; archival does not. Brief §8 requires archival before pruning whenever longer retention is configured, and states the pruning workflow plus chain anchors are not a one-year evidence archive.                                         |
| Backup and restore                          | **NOT-RUN**         | No backup schedule, no restore exercise. Brief §11 requires both.                                                                                                                                                                                     |

## Notifications

| Integration                       | Status              | Evidence / blocker                                                                                                                      |
| --------------------------------- | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Signed outbound webhooks          | **VERIFIED**        | HMAC signing with `timingSafeEqual` verification, replay/expiry validation, delivery retries via Temporal; `test/webhooks.e2e-spec.ts`. |
| Webhook egress SSRF safety        | **VERIFIED**        | Now uses the same redirect-aware outbound fetch as HTTP tools.                                                                          |
| Email / Slack / Teams / PagerDuty | **NOT-IMPLEMENTED** | Not built, not advertised. Listed only so the absence is explicit.                                                                      |

## Demo / reference tools

These exist to prove the gateway architecture end to end and to hold
regression value. **None of them is a vendor integration**, and none is
counted toward the integration gate.

| Fixture                                                        | Status           |
| -------------------------------------------------------------- | ---------------- |
| Demo SIEM (`packages/demo-soc-tools`)                          | **DEMO-FIXTURE** |
| Demo EDR — includes `isolate-host` (`mutating`, `destructive`) | **DEMO-FIXTURE** |
| Demo IAM — includes `disable-user` (`destructive`)             | **DEMO-FIXTURE** |
| Demo firewall                                                  | **DEMO-FIXTURE** |
| Reference MCP server (`test/support/mcp-test-server.ts`)       | **DEMO-FIXTURE** |

The demo EDR and IAM fixtures are the ones that make `BLOCKERS.md` B7
(retries repeating non-idempotent actions) concrete rather than theoretical:
the release ships actions declared `mutating`/`destructive`, and the adapter
currently retries them on an ambiguous timeout.

---

## What this matrix means for the release gate

Brief §11's gate is "every release integration has the required passing
evidence; missing access is an explicit blocker, not a pass."

**No AI provider profile is currently VERIFIED**, and no third-party vendor
integration exists to verify. The honest position, per brief §7's closing
paragraph, is:

- The protocol and connector infrastructure is implemented and tested.
- The exact missing input is **either** a real vendor specification and test
  tenant, **or** an owner decision on which connectors are in release scope.
- Two AI provider verifications are achievable in this workspace without any
  external access and should be done next: a genuine local Ollama run via
  `pnpm infra:up:ai`, and a real mTLS handshake between manar-api and
  manar-ai. Both are currently BLOCKED only because they have not been run,
  not because anything prevents them.

Until then the integration gate is **open**, and the release is not
integration-complete.
