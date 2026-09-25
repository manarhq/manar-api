# ADR-0004 — Microsoft connectors run as a third tool protocol behind the existing credential broker

- **Status:** ACCEPTED
- **Date:** 2026-09-25
- **Phase:** 2 (broker-executes connectors), as amended by Addendum 01 §A
- **Deciders:** engineering judgement; pilot scope from the 24 Sep pilot decisions (`../docs/Decisions.md`)

## Context

A paid pilot (go-live 11 Nov 2026, enforcing mode) will let an LLM SOC agent act on the customer's
Microsoft tenant through Manar: disable users, revoke sessions, reset passwords, isolate devices,
and read incidents, alerts and sign-ins. Customer credentials are not available yet.

The generic broker-executes path already exists and is tested: `POST /agent/v1/tools/invoke`
(`src/tools/tool-invoke.controller.ts`) → `AuthorizationService` (kill switches, task, OpenFGA,
policy, risk) → approval workflow and single-use grant when required → `CredentialBrokerService`
(`src/tools/credential-broker.service.ts`: `tool.invocation.started` audit before anything,
DLP before the call, credential from OpenBao via `SecretProvider`, `SUCCESS`/`FAILURE`/`UNKNOWN`
invocation row) → a `ToolProtocolAdapter` (`HttpToolAdapter`, `McpToolAdapter`). Addendum 01 §A
says Phase 2 extends this gateway rather than building a new one. What was missing is
Microsoft-specific: an OAuth2 client-credentials token provider with a cache, and a typed
catalog of Graph and Defender actions.

## Decision

1. **A third protocol, not a new pipeline.** `ToolProtocol` gains `MICROSOFT` (additive tenant
   migration `20260925120000_add_tool_protocol_microsoft`). `CredentialBrokerService` dispatches
   it to `MicrosoftToolAdapter` (`src/tools/microsoft-tool.adapter.ts`). Everything before the
   adapter (policy, approvals, kill switches, audit, DLP, fail-closed, R1's `UNKNOWN` rule) is
   unchanged and applies as-is.
2. **One tool per Microsoft API.** A tenant gets two `Tool` rows: `microsoft-graph`
   (`baseEndpoint` `https://graph.microsoft.com/v1.0`) and `microsoft-defender`
   (`https://api.securitycenter.microsoft.com/api`). `Tool.metadata` holds the non-secret
   settings, validated at every call: `api` (`graph` | `defender`), `azureTenantId`, `clientId`,
   `authorityUrl` (default `https://login.microsoftonline.com`), `requestTimeoutMs` (default
   15 s), plus the `dataOrigin` label. Tests and the DEMO FIXTURE point `baseEndpoint` and
   `authorityUrl` elsewhere.
3. **The catalog is code.** `src/tools/microsoft-actions.ts` defines every action: API, flags,
   base risk, required application permissions, JSON Schema for `params`, and the request
   builder. The adapter executes only actions named there, validates against the code schema
   (not the `ToolAction` row), and treats an action as side-effecting if either the catalog or
   the row says so. The seed writes `ToolAction` rows from the same list, so policy and risk see
   the same flags.
4. **The target is the authorized `resource`.** The user, device, incident, alert or
   machine-action id in the URL (or in `userIds`, or in the `$filter`) is always `resource`,
   which task resource selectors and approval grants are bound to, never a value in `params`.
   Each action has a pattern for `resource` (GUID, UPN, 40-hex machine id, numeric incident
   id), checked before any network call, and path segments are URL-encoded.
5. **Credentials.** The Entra app's client secret is the tool's credential: stored in OpenBao KV
   (`{ value: <secret> }`), resolved by the broker per call, handed to the adapter only for the
   token request. Tokens come from `POST {authorityUrl}/{tenant}/oauth2/v2.0/token` with
   `grant_type=client_credentials` and one scope per API (`https://graph.microsoft.com/.default`,
   `https://api.securitycenter.microsoft.com/.default`). They are cached in process memory until
   60 s before expiry, keyed by a SHA-256 over authority, tenant, client id, scope **and secret**
   (a tool never reuses a token cached for other credentials), evicted on a 401, and never
   persisted, logged or returned. Concurrent callers share one in-flight token request.
6. **Transport.** Every request, the token request included, goes through `safeOutboundFetch`
   (SSRF policy, per-hop checks, credential stripping on cross-origin redirects, bounded
   bodies) with a deadline that covers the body. Plain `http:` is refused unless
   `SSRF_ALLOW_LOOPBACK` (development only) is on, so neither secret nor token can travel in
   clear text in production.
7. **Outcomes.** Reads: up to 3 attempts on 429/5xx/network errors. Mutating or destructive: one
   attempt. No token → definite `FAILURE` (`token_acquisition_failed`); the action was never
   sent. After sending: timeout, dropped connection or 5xx → `outcomeUnknown` (`UNKNOWN`
   invocation, `tool.invocation.outcome_unknown` audit event); any other 4xx, and 429 on a
   mutation, → definite `FAILURE` carrying Microsoft's `error.code` only (never the message,
   which can echo request data).
8. **Password reset without revealing a password.** `entra.user.password.reset` sets a random
   36-character password Manar never returns, logs or stores, and forces a change at next
   sign-in. It locks the current holder of the password out; the user recovers through
   self-service reset or the helpdesk.
9. **Fixture first, labelled.** Until customer credentials arrive, the catalog is exercised
   against the DEMO FIXTURE in `packages/demo-soc-tools/src/microsoft/` (served by the existing
   demo-soc-tools container under `/microsoft`). `pnpm manar demo:seed --microsoft-fixture-url`
   registers both tools with `metadata.dataOrigin = "DEMO_FIXTURE"` and a description that says
   so. Switching to the customer tenant changes only `baseEndpoint`, `metadata` and the OpenBao
   secret, not the tool or action names, so policies and task grants carry over.

## Alternatives considered

- **Reuse `HttpToolAdapter` with the Microsoft endpoints as HTTP tools.** Its wire format is fixed
  (`POST {base}/{action}` with `{resource, params}`), it has no token exchange, and the
  credential would have to be a long-lived bearer token. Rejected.
- **An MCP server in front of Graph/Defender.** Moves the Microsoft client and credential into a
  second process Manar would have to secure and audit; adds a hop with no gain. Rejected for the
  pilot.
- **Catalog rows as the source of truth** (request templates in `ToolAction`). Anyone who can
  write a row could then point a call at any Graph path. Code keeps the executable surface
  reviewable. Rejected.
- **A new `ConnectorModule` and `POST /v1/tasks/{id}/actions`** (spec §6.1–6.2). A second
  decision path next to the gateway; Addendum 01 §A says extend the gateway. Deferred.
- **Microsoft SDKs (`@azure/identity`, `@microsoft/microsoft-graph-client`).** Would bypass the
  SSRF guard and bring token caches we do not control. Three HTTP calls do not need them.
- **Certificate (`private_key_jwt`) client credentials.** Dropped before 11 Nov by the pilot
  decisions; the token request is the only place that would change.
- **Do nothing until credentials arrive.** Leaves no time to build and review before 11 Nov.

## Consequences

- The agent never holds a Microsoft credential or client: it calls `/agent/v1/tools/invoke`.
- Adding an action is a code change with a review, not a data change.
- The catalog has not run against a live tenant. Request shapes and permissions follow
  Microsoft's public documentation and are proven only against the fixture. Known gaps:
  - Defender response actions are asynchronous; `SUCCESS` means Defender accepted the action
    (201, `Pending`), not that the device is isolated. `defender.machineaction.get/list`
    reads the real status; the fixture completes actions at once.
  - An app-only token cannot disable or reset the password of a user with a privileged Entra
    role unless the app itself holds a sufficient Entra role; expect 403s there.
  - Sign-in logs need Entra ID P1, Identity Protection actions need P2.
  - "Require MFA re-registration" is not implemented: Graph has no single call; it takes
    listing and deleting each authentication method (`UserAuthenticationMethod.ReadWrite.All`),
    in an order that respects the default method, and is not atomic. It should be built and
    tested against a live tenant, not the fixture.
  - Throttling: reads retry at a fixed 200 ms, without honouring `Retry-After`.
  - `UNKNOWN` outcomes still need manual reconciliation (R1); for Defender, the machine-action
    reads are the reconciliation tool.
- Operational: the token cache is per process; each API replica fetches its own tokens.
- Rollback: disable or delete the `MICROSOFT` tools; the enum value cannot be dropped without
  recreating the type (see the migration's note).

## Enforcement-label impact

None. The same enforcement path now reaches Microsoft actions; no AI system changes label. The
Microsoft connector itself is `IMPLEMENTED_TESTED` against the DEMO FIXTURE only and is **not
verified against a live tenant**; it must not be described as a live integration until it is.
