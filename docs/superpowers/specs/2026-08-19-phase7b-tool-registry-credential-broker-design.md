# Phase 7b: Tool Registry, Credential Broker & Proxy Execution — Design

Status: Approved (autonomous execution)
Scope: `manar-api` only
Depends on: Phase 6 (`PolicyEngine`/`RiskEngine` wired into
`AuthorizationService`). Runs in parallel with Phase 7a (demo tool
backends) — this phase's own tests use a lightweight local HTTP fixture
server it spins up itself; it does not depend on 7a's actual service
existing yet. A short follow-up integration pass wires the two together
and points the real `Tool` registry rows at Phase 7a's real service.

## Purpose

Sections 33-35: a first-class tool registry, a credential broker that
never lets an agent see the underlying tool credential, and an adapter
architecture that puts both HTTP tools and MCP tools through the exact
same authorization pipeline. This is where "authorize" (Phase 5/6)
becomes "actually execute something and prove the credential never
leaked."

## Data model (tenant DB)

- `Tool`: `id`, `name`, `type` (free text, e.g. `SIEM`/`EDR`/`IAM`/
  `FIREWALL`), `vendor`, `description`, `baseEndpoint`, `protocol` (enum
  `HTTP | MCP`), `credentialReference` (a `SecretReferenceDescriptor` —
  reuses Phase 2's `SecretProvider` interface), `enabled` (bool),
  `metadata` (Json).
- `ToolAction`: `id`, `toolId` (FK), `name`, `description`,
  `riskBaseScore` (0-100), `inputSchema`/`outputSchema` (Json, Zod-
  derived or plain JSON Schema — your call, document it), `mutating`
  (bool), `destructive` (bool), `approvalDefault` (bool).
- `ToolInvocation`: `id`, `taskId` (FK), `agentId` (FK), `toolId`,
  `actionId`, `resource`, `status` (enum `SUCCESS | FAILURE`),
  `startedAt`, `completedAt`, `errorMessage` (nullable). This is an
  **operational record**, not the tamper-evident audit chain (that's
  Phase 9) — don't build hash-chaining here, just enough to show a tool
  call happened and what it did. Never store raw request/response bodies
  that might contain credentials — store shape/summary only.

Migration.

## `SecretProvider`: add `OpenBaoSecretProvider`

Phase 2 defined the interface with only `EnvSecretProvider`; Phase 4
reserved `OPENBAO` as a provider value but didn't implement it. Implement
it now using OpenBao's KV secrets engine (research current official
docs — v1 vs v2 KV, path conventions) to store each tool's credential.
`CredentialBrokerService` resolves a `Tool.credentialReference` through
whichever provider it names — callers never know or care which backend
actually held it.

## `ToolProtocolAdapter` interface + implementations

```ts
interface ToolProtocolAdapter {
  invoke(
    tool: Tool,
    action: ToolAction,
    resource: string,
    params: unknown,
    credential: string,
  ): Promise<ToolInvocationResult>;
}
```

- `HttpToolAdapter`: makes the actual HTTP call to `tool.baseEndpoint`
  with the resolved credential injected as the auth header, request
  params validated against `ToolAction.inputSchema` before sending.
  Timeouts and basic retry-on-transient-failure (document the policy,
  keep it simple — no exponential-backoff framework needed here).
- `McpToolAdapter`: a **real** MCP client (research the Model Context
  Protocol's current official TypeScript SDK/spec — don't approximate
  JSON-RPC by hand if an official SDK exists) capable of connecting to
  an MCP server and invoking a tool call through it. Prove this works
  against a minimal test MCP server you also build for this phase's
  tests (it does not need to be one of Phase 7a's SOC tools — a trivial
  MCP server exposing one tool is sufficient to prove the adapter
  architecture is real, not scope-creep into a second full demo tool
  suite). Every MCP call still goes through the same
  `CredentialBrokerService`/`AuthorizationService` pipeline as HTTP tools
  — no separate, weaker path for MCP (Section 35's explicit requirement).

## `CredentialBrokerService`

`invoke({ taskId, agentId, toolId, actionId, resource, params }) → ToolInvocationResult`:

1. Loads `Tool`/`ToolAction`, confirms `Tool.enabled`.
2. Resolves the credential via `SecretProvider` (never logged, never
   included in any response to the agent).
3. Calls the appropriate `ToolProtocolAdapter` (`HTTP` or `MCP` based on
   `Tool.protocol`).
4. Records a `ToolInvocation` row (success/failure, timing — no secrets,
   no raw payloads).
5. Returns the tool's result to the caller — **the credential is never
   part of that return value under any code path**; write a test that
   proves this by construction (grep the actual response object/serialized
   JSON in the test), not by inspection.

## Wiring: `POST /agent/v1/tools/invoke`

New mTLS-guarded endpoint, the first one that actually _does_ something
beyond deciding. Body: `{ taskId, toolId, actionId, resource, params }`.

1. Calls the existing `AuthorizationService` (Phase 5/6, unchanged) to
   get `ALLOW | DENY | REQUIRE_APPROVAL`.
2. `DENY` → 403 with reason, no tool call attempted.
3. `REQUIRE_APPROVAL` → 202/appropriate status indicating pending, no
   tool call attempted (Phase 8 will later give this a real fulfillment
   path — still a dead end here, same as Phase 6 left it).
4. `ALLOW` → `CredentialBrokerService.invoke(...)`, return its result.

Do not duplicate or fork the authorization pipeline — this endpoint is a
thin wrapper that calls into the existing service and then, only on
`ALLOW`, proceeds to execution.

## `RiskEngine` follow-up (closes Phase 6's documented gap)

Phase 6 used a placeholder keyword heuristic on `actionId` for
mutating/destructive signal, explicitly noting it'd be replaced once a
real Tool Registry existed. Replace it now: `RiskEngine.score` should
look up the real `ToolAction.riskBaseScore`/`mutating`/`destructive`
fields instead of guessing from the action name string. Remove the old
heuristic entirely — don't leave dead code behind "just in case."

## Docs

`docs/tool-gateway.md` and `docs/mcp.md` (both required by Section 87),
covering the registry schema, the credential-broker flow, and the MCP
adapter architecture.

## Testing

- Register a tool + action pointing at a lightweight local HTTP fixture
  server (built for this test, standing in for Phase 7a's real service);
  full authorize→invoke round trip returns the tool's real response.
- The same, via `McpToolAdapter` against the minimal test MCP server —
  proves MCP goes through the identical pipeline (not a parallel one).
- Credential never appears in the HTTP response to the agent, in any log
  line, or in the stored `ToolInvocation` row — assert by inspecting
  actual captured output/DB rows, not by code review.
- `DENY` from `AuthorizationService` → no HTTP/MCP call is made at all
  (assert the fixture server received zero requests).
- `REQUIRE_APPROVAL` → same, no call made, and the response clearly
  signals "pending," not success or failure.
- Disabled tool (`enabled: false`) → invocation fails cleanly even if
  authorization would otherwise allow it.
- `ToolInvocation` rows are created for both success and failure cases,
  never containing raw request/response payloads.
- Existing Phase 5/6 e2e suites still pass unmodified.

## Out of scope this phase

- Any real connection to Phase 7a's actual demo tool service (integration
  pass, done separately once both land)
- Approval fulfillment for `REQUIRE_APPROVAL` (Phase 8)
- Full audit hash chain (Phase 9) — `ToolInvocation` is operational only
- Rate limiting / retry-with-backoff frameworks beyond a simple policy
