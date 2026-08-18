# MCP (Model Context Protocol) adapter

This is `manar-api`'s implementation of the MCP half of Phase 7b's tool
adapter architecture (Section 35 of the master prompt: "MCP goes through
the identical authorization/credential-broker pipeline — no separate,
weaker path"). See `docs/tool-gateway.md` for the broader
registry/credential-broker/wiring picture this fits into.

## SDK: `@modelcontextprotocol/sdk`

The official Model Context Protocol TypeScript SDK — one package,
`@modelcontextprotocol/sdk` (confirmed via `npm view
@modelcontextprotocol/sdk` and the installed package's own `dist/`
layout, rather than trusting web-search summaries, which — at the time
this phase was built — repeatedly hallucinated a nonexistent split into
separate `@modelcontextprotocol/server`/`@modelcontextprotocol/client`
packages; the real package uses subpath exports instead, e.g.
`@modelcontextprotocol/sdk/server/mcp.js`,
`@modelcontextprotocol/sdk/client/streamableHttp.js`). Selected version
`^1.30.0`. This is a real client implementing MCP's actual JSON-RPC wire
format and lifecycle (`initialize` → `notifications/initialized` → tool
calls) — not an approximation hand-rolled against the spec, per the
design spec's explicit instruction.

- **Server side** (test fixture only — see below): `McpServer`
  (`@modelcontextprotocol/sdk/server/mcp.js`) + `StreamableHTTPServerTransport`
  (`@modelcontextprotocol/sdk/server/streamableHttp.js`).
- **Client side** (the real adapter): `Client`
  (`@modelcontextprotocol/sdk/client/index.js`) +
  `StreamableHTTPClientTransport`
  (`@modelcontextprotocol/sdk/client/streamableHttp.js`).
- **Transport**: Streamable HTTP (the current MCP transport for
  network-reachable servers — stdio is for a locally-spawned child
  process, not applicable here since a `Tool.baseEndpoint` is a URL).

## `McpToolAdapter`: the real client

`src/tools/mcp-tool.adapter.ts`. For each invocation:

1. Validates `params` against `action.inputSchema` (same `ajv`-based
   check `HttpToolAdapter` uses — see `docs/tool-gateway.md`).
2. Constructs a fresh `Client` + `StreamableHTTPClientTransport(new
URL(tool.baseEndpoint), { requestInit: { headers: { Authorization:
\`Bearer ${credential}\` } } })` — the resolved credential is injected
   as a header on the transport's own outbound HTTP requests, **never**
   as a JSON-RPC tool-call argument (so it can never appear in an MCP
   tool's own request logging of its arguments, and never round-trips
   through the JSON-RPC message layer at all).
3. `client.connect(transport)`, then `client.callTool({ name:
action.name, arguments: { resource, ...params } }, undefined, {
timeout: 10_000 })`.
4. On `result.isError`, returns `{ success: false, errorMessage }`
   (summarized from any `text`-typed content items). Otherwise `{
success: true, data: result.structuredContent ?? result.content }`.
5. Always closes the client in a `finally` block, whether the call
   succeeded, failed, or threw.

A fresh connection per invocation (not a pooled/persistent session) —
simpler and correct for this phase's call volume; documented as a
deliberate simplification.

## The test MCP server: `test/support/mcp-test-server.ts`

A minimal, **real** MCP server (`McpServer` + `StreamableHTTPServerTransport`
— not a hand-rolled JSON-RPC stand-in) exposing exactly one tool,
`lookup`, built for this phase's own tests to prove `McpToolAdapter`'s
architecture is real end-to-end. Deliberately **not** one of Phase 7a's
demo SOC tools — the design spec is explicit that this phase's own tests
must not depend on that service existing yet, and a trivial one-tool
server is sufficient to prove the adapter is real (not scope creep into a
second full demo tool suite).

The `lookup` tool records every call it receives (arguments, and the
`Authorization` header the underlying HTTP request carried — via
`extra.requestInfo.headers` in the tool callback — proving credential
injection actually reached the wire, not just that `McpToolAdapter`
intended to send it) and echoes back `{ found: true, resource }` as both
`content` (a JSON-stringified text block) and `structuredContent`.

### A real bug this phase's tests caught: one transport instance can't be reused across a client's initialize → notify → call sequence

The SDK's own doc comment for `StreamableHTTPServerTransport` shows a
single long-lived transport instance handling every request in stateless
mode (`sessionIdGenerator: undefined`):

```ts
const statelessTransport = new StreamableHTTPServerTransport({
  sessionIdGenerator: undefined,
});
app.post('/mcp', (req, res) => {
  transport.handleRequest(req, res, req.body);
});
```

Reproduced against a bare `node:http` server (no Nest/Fastify involved),
this pattern works for the client's first request (`initialize`) but the
server responds **HTTP 500** to the client's very next request — the
`notifications/initialized` notification every MCP client sends
immediately after a successful `initialize` — confirmed empirically
against `@modelcontextprotocol/sdk@1.30.0`'s bundled `@hono/node-server`
Node-compatibility wrapper (`dist/esm/server/streamableHttp.js`), not
merely suspected: a minimal repro script isolating just the SDK's server
and client classes against each other reproduces it deterministically,
with no application code involved at all.

**Fix**: build a fresh `McpServer` + fresh stateless
`StreamableHTTPServerTransport` **per incoming HTTP request** instead of
reusing one instance across a client's whole session — connect, handle
that one request, and let both get garbage-collected once the response's
`res.on('close', ...)` fires. This is both a documented-elsewhere pattern
for genuinely stateless MCP HTTP servers (e.g. serverless/edge
deployments that can't hold in-memory session state across invocations
anyway) and reliably avoids the observed 500. `McpToolAdapter` itself
already connects fresh per invocation (see its own doc comment) — the
test server's per-request pattern matches the client's actual usage,
it isn't a workaround grafted on only for the test double.

## A real bug this phase's tests caught: the workload-identity CN length limit applies to test agent slugs too

Unrelated to MCP itself, but caught while writing `test/tool-gateway.e2e-spec.ts`:
`packages/sdk-node/src/csr.ts` sets a CSR's Common Name to the full agent
identifier (`agent://<tenantSlug>/<slug>`), and OpenBao's `sign-verbatim`
role validation rejects a CN longer than 63 octets with `"idna: invalid
label"` (confirmed empirically: 63 octets signs successfully, 64 fails,
against the exact same identifier shape) — a pre-existing Phase 4
constraint, not something this phase changed. This phase's own test slug
labels stay comfortably under that limit as a result (documented inline
at the one call site that was originally long enough to trip it).

## Out of scope this phase

- Any MCP transport other than Streamable HTTP (e.g. stdio, SSE-only
  legacy transport) — not applicable to a `Tool.baseEndpoint` URL.
- MCP resources/prompts (only the tools capability is used).
- Persistent/pooled MCP client sessions across invocations.
- Any of Phase 7a's actual demo SOC tool MCP servers, if any exist — a
  later integration pass.
