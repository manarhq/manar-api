# Tool gateway: registry, credential broker & proxy execution

This is `manar-api`'s implementation of Phase 7b (Tool Registry,
Credential Broker & Proxy Execution):
`docs/superpowers/specs/2026-08-19-phase7b-tool-registry-credential-broker-design.md`,
Sections 33-35. This is where "authorize" (Phase 5/6 —
`docs/authorization-model.md`, `docs/policy-model.md`) becomes "actually
execute something, and prove the credential never leaked." See
`docs/mcp.md` for the MCP-specific half of the adapter architecture.

## Data model (tenant DB)

`prisma/tenant.prisma`, migration
`20260818204554_add_tool_registry_and_credential_broker`:

- **`Tool`**: `id`, `name` (unique per tenant database — see "`toolId`
  still means the same thing it always did" below), `type` (free text,
  e.g. `SIEM`/`EDR`/`IAM`/`FIREWALL` — a category label, never matched
  against by any authorization/risk logic), `vendor`, `description`,
  `baseEndpoint`, `protocol` (`HTTP | MCP`), `credentialReference` (a
  `SecretReferenceDescriptor` — see "Credential resolution" below),
  `enabled`, `metadata` (`Json`, free-form, never interpreted).
- **`ToolAction`**: `id`, `toolId` (FK), `name` (unique per `toolId`),
  `description`, `riskBaseScore` (0-100), `inputSchema`/`outputSchema`
  (`Json` — see "Input schema format" below), `mutating`, `destructive`,
  `approvalDefault` (carried in the schema for future policy-authoring
  ergonomics; not read by `RiskEngine`/`AuthorizationService` this
  phase — `PolicyEngine`/`RiskEngine`'s own `REQUIRE_APPROVAL` routing
  stays the single source of truth for that decision, see
  `docs/policy-model.md`).
- **`ToolInvocation`**: `id`, `taskId`/`agentId`/`toolId`/`actionId`
  (real FKs), `resource`, `status` (`SUCCESS | FAILURE`), `startedAt`,
  `completedAt`, `errorMessage`. An **operational record** — not the
  tamper-evident audit hash chain (Phase 9's scope). Never stores the
  resolved credential, a raw request body, or a raw response body —
  only shape/summary (`resource` is an identifier string, `errorMessage`
  is a short fixed/derived summary like `"HTTP 503"` or `"Tool is
disabled"`, never the tool's actual response text).

### `toolId`/`actionId` still mean the same thing they always did

Phase 5/6's `Task.allowedToolActions[].toolId`/`AuthorizeRequest.toolId`
(and `actionId`) were always opaque, caller-supplied strings, validated
only for a safe slug-like shape
(`src/authorization/grant-triples.ts`'s `ToolActionSchema`) — never
resolved against a real catalog (see docs/authorization-model.md's "out
of scope" note). This phase does **not** change that contract: no schema
change to `Task`, `AuthorizeRequest`, or the OpenFGA model. What changes
is that those same strings now _may_ also resolve against a real
`Tool.name`/`ToolAction.name` row, once one has actually been registered
— `ToolRegistryService.findToolAction(tenantClient, toolId, actionId)`
(`src/tools/tool-registry.service.ts`) does exactly this lookup, and
returns `null` (never throws) when nothing is registered for that pair —
a normal, expected outcome for the majority of Phase 5/6's own
pre-existing tests, which never registered a real tool at all, and for
any future request whose task grant simply predates a tool's
registration. This is the same "no match is not a failure" posture
`PolicyEngine` already established for policy rules (docs/policy-model.md).

There is no human-facing API to register a `Tool`/`ToolAction` this
phase (out of scope — a later phase's tool-registry management surface).
This phase's own tests write these rows directly against the real tenant
database, the same way `test/policy-risk.e2e-spec.ts`'s "simulated
policy-load failure" scenario writes a corrupt `PolicyVersion` directly
when no API path exists to produce one.

### Input schema format: plain JSON Schema, not a serialized Zod schema

`ToolAction.inputSchema` is plain JSON Schema (validated at invocation
time via `ajv` — `src/tools/json-schema-validator.util.ts`), not a
serialized Zod schema. Zod schemas aren't JSON-serializable; JSON Schema
is the interoperable, storable, tool-vendor-agnostic choice, and is also
what the MCP ecosystem itself expects a tool's declared input contract to
look like. `null`/absent means "no schema declared — skip validation
entirely," not "reject everything."

## Credential resolution: `OpenBaoSecretProvider`

Phase 2 defined the `SecretProvider` interface
(`src/database/secret-provider.ts`) with only `EnvSecretProvider`; Phase
4 reserved `OPENBAO` as a valid `SecretReference.provider` value but
never implemented it. This phase implements it:

- **`OpenBaoKvClient`** (`src/openbao/openbao-kv.client.ts`): a thin,
  mechanical wrapper around OpenBao's KV v2 secrets engine HTTP API
  (verified directly against a real local OpenBao server while building
  this — `GET/POST /v1/<mount>/data/<path>`, response wrapped in
  `{ data: { data: {...}, metadata: {...} } }`). `OPENBAO_KV_MOUNT_PATH`
  (default `secret`) names the mount — OpenBao's own `-dev` mode already
  auto-mounts a `kv-v2` engine at `secret/`, but `deploy/openbao-init.mjs`
  still enables it explicitly and idempotently (mirroring how it already
  handles the PKI engines), since a non-dev deployment has no such
  default.
- **`OpenBaoSecretProvider`** (`src/database/openbao-secret-provider.ts`):
  owns exactly one convention on top of the raw KV client — a tool
  credential's value is always stored under the fixed key `"value"` in
  that secret's `data` object (mirroring `EnvSecretProvider`'s "one
  opaque string per reference" shape). The same "Manar owns policy, the
  external system only does the mechanical operation" posture
  `CertificateAuthorityService`/`OpenBaoPkiClient` establish for PKI
  (`docs/agent-identity.md`) — there is far less policy to own here (no
  CSR/subject to validate), but the shape of the split is the same.
- **`CompositeSecretProvider`** (`src/database/composite-secret-provider.ts`):
  what `DatabaseModule` now binds the `SECRET_PROVIDER` DI token to.
  Dispatches `resolve(ref)` to `EnvSecretProvider` or
  `OpenBaoSecretProvider` based on `ref.provider` — this is what makes
  "`CredentialBrokerService` resolves a `Tool.credentialReference`
  through whichever provider it names, transparently" literally true:
  `CredentialBrokerService` holds one injected `SecretProvider` and never
  branches on `provider` itself. `TenantDatabaseManager`'s own
  ENV-only tenant-DB-secret resolution is unaffected — it still only ever
  passes `ENV` references, which `CompositeSecretProvider` still routes to
  `EnvSecretProvider` exactly as before.

A tool's credential is provider-agnostic from `CredentialBrokerService`'s
point of view — a `Tool` row can equally point at an `ENV` variable or an
OpenBao KV v2 secret, and switching one tool from one to the other is a
one-row `credentialReference` update, no code change.

## `ToolProtocolAdapter` architecture

```ts
interface ToolProtocolAdapter {
  invoke(
    tool: ToolRecord,
    action: ToolActionRecord,
    resource: string,
    params: unknown,
    credential: string,
  ): Promise<ToolInvocationResult>;
}
```

(`src/tools/tool-protocol-adapter.interface.ts`). `ToolInvocationResult`
is `{ success: boolean; data?: unknown; errorMessage?: string }` — by
construction, no code path in either adapter ever puts `credential` into
this object (see "Credential secrecy" below).

### `HttpToolAdapter` (`src/tools/http-tool.adapter.ts`)

A single `POST` to `new URL(action.name, tool.baseEndpoint)` — i.e.
`baseEndpoint` is treated as a base URL and `action.name` is appended as
a relative path segment (a tool with multiple actions registers one
`Tool` row and one `ToolAction` row per action, all sharing the same
`baseEndpoint`). Request body: `{ resource, params }` (JSON). The
resolved credential is injected as `Authorization: Bearer <credential>`.

`params` is validated against `action.inputSchema` **before** any network
call — an invalid payload never reaches the network at all (no wasted
retry budget, no partial side effect on the target tool).

**Timeout/retry policy** (Section 35: "keep it simple — no
exponential-backoff framework needed"): a 10s timeout per attempt, up to
3 total attempts, a fixed 200ms delay between retries. Retried only on a
network-level failure (`fetch` itself rejecting — DNS, connection
refused, timeout) or an HTTP 5xx response; a 4xx is never retried (the
tool's own considered answer that this specific request is invalid).
This is **not** safe for non-idempotent actions in general — a POST that
partially succeeded server-side before the response was lost would be
retried verbatim. Acceptable for this phase's scope per the design spec;
a real integration wanting idempotency would need the target tool to
support an idempotency key, out of scope here.

### `McpToolAdapter` (`src/tools/mcp-tool.adapter.ts`)

A **real** MCP client — the official `@modelcontextprotocol/sdk`
TypeScript SDK (`Client` + `StreamableHTTPClientTransport`), not a
hand-rolled approximation of MCP's JSON-RPC wire format. See
`docs/mcp.md` for the full detail on why this SDK and how it's used;
this document covers only how it fits into the gateway:

- Connects to `tool.baseEndpoint` as an MCP server URL, calls
  `action.name` as an MCP tool, `{ resource, ...params }` as its
  arguments.
- The resolved credential is injected as an `Authorization: Bearer`
  header on the transport's own underlying HTTP requests
  (`requestInit.headers`) — MCP's base protocol has no first-class "auth"
  concept of its own; this mirrors `HttpToolAdapter`'s bearer-token
  convention, applied at the transport layer instead of a tool argument,
  so it can never appear in an MCP tool's own request logging of its
  arguments.
- `params` is validated against `action.inputSchema` before dispatch,
  exactly like `HttpToolAdapter` — Manar owns this validation boundary
  regardless of protocol, never trusting the target tool to reject a
  malformed call.
- Connects fresh per invocation (new `Client` + transport, closed again
  after) rather than pooling a persistent MCP session — simpler and
  correct for this phase's call volume; documented as a deliberate
  simplification, not an oversight.

**Every MCP call goes through the exact same `CredentialBrokerService`/
`AuthorizationService` pipeline as an HTTP call** — Section 35's explicit
requirement. There is no branch anywhere (in `CredentialBrokerService`,
in `POST /agent/v1/tools/invoke`, or in `AuthorizationService` itself)
that treats `Tool.protocol === 'MCP'` any differently from `'HTTP'`
except "which adapter's `invoke` gets called."

## `CredentialBrokerService`

`src/tools/credential-broker.service.ts`. `invoke({ taskId, agentId,
toolId, actionId, resource, params })`:

1. **Loads `Tool`/`ToolAction`** (`ToolRegistryService`) — throws
   `ToolNotFoundError`/`ToolActionNotFoundError` if either doesn't
   resolve. No `ToolInvocation` row is possible at this point (its
   `toolId`/`actionId` columns are real foreign keys — there's nothing
   valid to reference yet).
2. **Confirms `Tool.enabled`** — a disabled tool fails invocation cleanly
   even though `AuthorizationService` already ALLOWed (tool enablement is
   an operational concern, not an authorization decision — Section 35's
   explicit requirement). Unlike step 1, both ids are known by now, so
   this _does_ record a `FAILURE` `ToolInvocation` row before throwing
   `ToolDisabledError`.
3. **Resolves the credential** via the injected `SecretProvider` — held
   only in a local variable for exactly as long as step 4 takes.
4. **Dispatches** to `HttpToolAdapter` or `McpToolAdapter` based on
   `Tool.protocol`.
5. **Records a `ToolInvocation` row** (`SUCCESS`/`FAILURE`, timing,
   `resource`, a short credential-free `errorMessage` on failure) —
   whether the adapter itself succeeded or failed. Never the resolved
   credential, never a raw request/response payload.
6. **Returns the adapter's `ToolInvocationResult` unchanged.**

### Credential secrecy: provable, not asserted

The resolved credential exists only as a local variable inside
`CredentialBrokerService.invoke` (step 3) and, transiently, as an HTTP
header value inside whichever adapter's `invoke` call it's passed to.
There is no code path that assigns it to a field of `ToolInvocationResult`
(the value returned to the caller) or to any argument of
`tenantClient.toolInvocation.create` (the persisted row). This is proven,
not merely asserted: `test/tool-gateway.e2e-spec.ts`'s scenario 4 spies on
`process.stdout.write` for the duration of a real invoke call, greps the
actual captured log output, the actual HTTP response body returned to the
agent, and the actual `ToolInvocation` row read back from the real tenant
database — all three must not contain the credential value.

## Wiring: `POST /agent/v1/tools/invoke`

`src/tools/tool-invoke.controller.ts` (`ToolInvokeModule`, imported only
into `AgentMtlsAppModule` — mTLS-guarded, mirroring `DelegationModule`'s
single-app shape). Body: `{ taskId, toolId, actionId, resource, params }`.

1. Calls the **existing, unchanged** `AuthorizationService.authorize(...)`
   (Phase 5/6) — this endpoint never forks or duplicates that pipeline.
2. `DENY` → HTTP 403, `{ decision: 'DENY', reason }`. No tool call is ever
   attempted.
3. `REQUIRE_APPROVAL` → HTTP 202, `{ status: 'PENDING', reason,
riskScore }` — a clearly-not-success, clearly-not-failure signal. No
   tool call is ever attempted. Phase 8 will give this decision a real
   fulfillment path; it's correctly a dead end here, the same as Phase 6
   left it at `/agent/v1/authorize`.
4. `ALLOW` → `CredentialBrokerService.invoke(...)`, whose
   `ToolInvocationResult` is returned as the response body (HTTP 200) —
   note this can itself be `{ success: false, ... }` if the _tool_ call
   failed; that's a request the gateway itself handled successfully,
   distinct from an authorization failure.
5. `ToolNotFoundError`/`ToolActionNotFoundError` → 404.
   `ToolDisabledError` → 409.

Unlike `POST /agent/v1/authorize` (which always answers 200/201 — see
`docs/authorization-model.md` — to avoid leaking _why_ through the HTTP
status code on an authorize-only surface a caller could otherwise probe),
this endpoint's `DENY` maps to a real 403 per the design spec: there's no
equivalent probing concern here, since this endpoint doesn't expose a
separate "just tell me the decision" surface a caller could compare
against.

## `RiskEngine` follow-up: real per-action risk metadata

Phase 6 shipped a placeholder keyword heuristic (`DESTRUCTIVE_KEYWORDS`,
a regex over `actionId` for words like `delete`/`isolate`/`terminate`),
explicitly documented as temporary. This phase deletes it entirely and
replaces it with real `ToolRegistryService.findToolAction` lookups
(`src/risk/risk-engine.service.ts`):

- **`tool_action_risk_base:<n>`**: the registered `ToolAction.riskBaseScore`,
  added directly.
- **`tool_action_mutating:<15>`** / **`tool_action_destructive:<25>`**:
  added independently when the corresponding boolean flag is `true` (a
  destructive action is also mutating, but the two flags are independent
  columns on the schema, so both contribute independently when both are
  set).
- **No registered `ToolAction` for `{ toolId, actionId }`** → contributes
  nothing at all, never a guess. This is what keeps every one of Phase
  5/6's own pre-existing tests (which never registered a real tool)
  authorizing identically — see docs/policy-model.md's updated Risk
  Engine section.

## Testing

`test/tool-gateway.e2e-spec.ts` runs every mandatory scenario from the
design spec's "Testing" section against real Postgres/Keycloak/OpenBao
(PKI + KV v2)/OpenFGA (`pnpm infra:up` + `pnpm infra:openbao-init`), plus
this phase's own local HTTP fixture server
(`test/support/http-fixture-server.ts`) and minimal test MCP server
(`test/support/mcp-test-server.ts` — see docs/mcp.md):

1. HTTP tool: full authorize→invoke round trip against the local HTTP
   fixture server returns the tool's real response.
2. MCP tool: the same, via `McpToolAdapter` against the test MCP server —
   proves MCP goes through the identical pipeline.
3. An `OPENBAO`-backed credential resolves transparently through
   `OpenBaoSecretProvider` (a real KV v2 secret is written via the real
   OpenBao HTTP API first).
4. The credential never appears in the HTTP response, in any captured log
   line, or in the stored `ToolInvocation` row.
5. `DENY` → zero requests reach the fixture server.
6. `REQUIRE_APPROVAL` (via a high `riskBaseScore` pushing the
   deterministic score above `task.riskCeiling` — the same mechanism
   `test/policy-risk.e2e-spec.ts`'s scenario 3 exercises, now fed by a
   real `ToolAction` instead of the deleted keyword heuristic) → zero
   requests, a `PENDING` response.
7. A disabled tool fails invocation cleanly even though authorization
   ALLOWs — a `FAILURE` `ToolInvocation` row is still recorded (both ids
   are known by then).
8. `ToolInvocation` rows exist for both a success and a failure case
   (the fixture server made to return 503 for the failure), and neither
   row contains the raw request/response payload markers the test plants.

Phase 5/6's existing e2e suites (`test/task-delegation.e2e-spec.ts`,
`test/policy-risk.e2e-spec.ts`) were re-run and pass unmodified in
behavior — the only changes were the same kind of trivial
constructor-argument update Phase 6 itself already made once
(`RiskEngine` gained a `ToolRegistryService` constructor parameter; test
call sites that construct it directly were updated to pass one).

## Out of scope this phase

- Any real connection to Phase 7a's actual demo tool service (a separate
  integration pass, once both land — this phase's tests use their own
  local fixture servers instead, per the design spec). **Done**: once
  both phases merged to `main`, this integration pass was completed —
  see `test/tool-gateway-demo-integration.e2e-spec.ts`, which registers a
  real `Tool`/`ToolAction` pointing at the real, running
  `packages/demo-soc-tools` container and independently re-verifies its
  state changed. `HttpToolAdapter`'s wire convention didn't line up with
  that service's original hand-rolled REST routes, so
  `packages/demo-soc-tools/src/routes/edr.ts` gained two small
  action-name wrapper routes (`POST /v1/edr/get-host`,
  `POST /v1/edr/isolate-host`) rather than special-casing the generic,
  already-tested adapter for one demo tool.
- Approval fulfillment for `REQUIRE_APPROVAL` (Phase 8).
- Full audit hash chain (Phase 9) — `ToolInvocation` is operational only.
- Rate limiting / retry-with-backoff frameworks beyond the simple policy
  described above.
- A human-facing `Tool`/`ToolAction` registration API.
