# ADR-0002 — The agent's LLM proxy, tool manifest and governed MCP server live in manar-api

- **Status:** ACCEPTED
- **Date:** 2026-09-25
- **Phase:** 1 (spec §5.2; Addendum 01 §C.3; Gate 0 adjustments 1, 3, 4 and findings S6, S7, S8, S29)
- **Deciders:** engineering judgement (placement follows Gate 0 adjustment 4, approved at Gate 0)

## Context

Phase 1 puts the SOC agent in a box whose only egress is manar-api. An LLM-driven agent
needs three things from that one egress: a model, the list of tools it may use, and a way
to call them. Before this ADR manar-api had the third only (`POST /agent/v1/tools/invoke`,
`src/tools/`), and the only DLP in the system lived in manar-ai behind an RPC that fails
open on `null` (Gate 0 S6).

The pilot's model is the customer's Azure OpenAI deployment (Decisions.md, 24 Sep); the
sovereignty demo runs fully local on Ollama (Addendum 01 §A). manar-ai does not hold an
Azure OpenAI client for agent use, so there is nothing to reuse there.

## Decision

All three surfaces are in manar-api, on the mTLS agent listener (`AgentMtlsAppModule`), in
`src/agent-runtime/`:

1. **LLM proxy** `POST /agent/v1/llm/chat/completions`, OpenAI-compatible, non-streaming.
   Per call, in order, each step fail-closed:
   1. `AgentMtlsGuard` (certificate, agent ACTIVE, not revoked).
   2. Task access (`AgentTaskAccessService`): kill switches (platform, tenant, agent, agent
      group, AI system SUSPENDED/RETIRED), task exists, assigned to this agent, it and every
      ancestor ACTIVE, inside its time window and under its execution limit. Same services
      and reason codes as steps 0–3 of `AuthorizationService`.
   3. Per-task token budget (`LLM_TASK_TOKEN_BUDGET`, default 200 000 upstream-reported
      total tokens) kept in Redis. Used ≥ budget → 429 `llm_budget_exhausted`.
   4. Deterministic DLP floor in-process (`src/common/dlp/dlp-classification.ts`, shared
      with the tool-result path, see "Result DLP" below): credential shapes **block**
      (JWT, bearer tokens, PEM private keys, Azure storage/Service Bus connection strings,
      SAS `sig=`, JSON `client_secret`/`password`/`secret` values, Entra client secrets);
      UAE PII is **redacted** to `[REDACTED:EMIRATES_ID]` / `[REDACTED:UAE_IBAN]` /
      `[REDACTED:PAYMENT_CARD]` (Luhn-checked) / `[REDACTED:UAE_MOBILE]` before the prompt
      goes anywhere, manar-ai included. Nesting deeper than 64 levels is not scanned and
      blocks as `scan_depth_exceeded`.
   5. manar-ai `AnalyzeDlp` on the redacted text. **`null` blocks** (503; S6 closed on this
      path). A non-`system` finding of type API key, private key, JWT or credential blocks.
      E-mail findings do not block: a SOC agent cannot reason about an incident without
      the user's UPN. `TYPE_PII` / `TYPE_OTHER` findings are **redacted in place** per
      string leaf before upstream (see "Result DLP", same code). The `source: "system"`
      marker never blocks (S7).
   6. Upstream `POST <base>/chat/completions`: `LLM_PROVIDER=ollama` (default,
      `LLM_OLLAMA_BASE_URL` default `http://localhost:11434/v1`, `LLM_MODEL` default
      `qwen3.5:9b`) or `azure_openai` (`LLM_AZURE_OPENAI_ENDPOINT`,
      `LLM_AZURE_OPENAI_DEPLOYMENT`, `LLM_AZURE_OPENAI_API_VERSION`, key from the
      `AZURE_OPENAI_API_KEY` environment variable, sent as `api-key` and nowhere else).
      The agent's `model` field is ignored.
   7. Usage is added to the budget; if the upstream reports none, a length/4 estimate is
      charged rather than nothing.
   8. Audit `llm.request` with metadata only: task id, provider, model, prompt/completion/
      total tokens, SHA-256 of the messages as received, latency, outcome, reason, DLP
      finding **types**, budget used/limit, message and tool counts. Never prompt or
      completion text, never DLP previews. On success the event is written with the
      throwing `record`; if it cannot be written the completion is not returned (503).
      Refusals are recorded best-effort.
2. **Tool manifest** `GET /agent/v1/tasks/:taskId/tool-manifest`: the task's effective
   grant set (own allowed actions × resource selectors, minus forbidden, intersected with
   every ancestor) restricted to registered actions of **enabled** tools. Same access gate
   as the proxy. Listing a tool is not an authorization; every call runs the full pipeline.
3. **Governed MCP server** `POST /agent/v1/tasks/:taskId/mcp`: MCP Streamable HTTP,
   stateless, JSON responses (a fresh SDK `Server` per request). `tools/list` is the
   manifest; `tools/call` runs `ToolInvocationService`, which is the code behind
   `POST /agent/v1/tools/invoke` moved out of its controller. One decision path, two doors.

**Result DLP** (owner decision 25 Sep 2026, "redact fields, not results"). Tool results
returned to the agent (`CredentialBrokerService.applyPostCallAdvisories`, so both
`tools/invoke` and MCP `tools/call`) go through the same classification as prompts, in the
same order: floor, then manar-ai `AnalyzeDlp` on the floor's redacted string leaves, then
`advisoryBlocks`. The two checkpoints cannot disagree; a unit test runs the same samples
through both.

- Credential (floor shape, or a non-`system` manar-ai finding of type API key, private key,
  JWT or credential) → the **whole result is withheld**:
  `{"redacted":true,"reason":"sensitive_data_detected","findingCount":N,"findingTypes":[...]}`.
- UAE PII (Emirates ID, UAE IBAN, payment card, UAE mobile) → **replaced in place** with
  `[REDACTED:<TYPE>]`; the rest of the JSON is returned.
- manar-ai `TYPE_PII` / `TYPE_OTHER` (non-`system`) → **the string leaf that carries the
  finding is replaced whole** with `[REDACTED:PII]` / `[REDACTED:OTHER]` (owner decision
  25 Sep, second half). **Granularity is the string leaf, not the span.** manar-ai's
  `DlpFinding` carries a type, a confidence and a model-written preview, no offsets, and
  `AnalyzeDlp` returns no redacted content; these types come only from manar-ai's model
  layer, so there is no pattern to re-apply. `classifyDlp` therefore locates the leaf by
  bisection: the distinct string leaves are split in halves and each flagged half is
  re-scanned until single leaves remain (about 2 × log2(leaves) extra `AnalyzeDlp` calls per
  flagged leaf, siblings in parallel, each under the hot-lane deadline), bounded by
  `DLP_LOCATE_MAX_CALLS` (32). Every occurrence of a flagged leaf value is replaced. A
  whole JSON field (e.g. `displayName`) goes, not just the name inside it; on the proxy
  path a leaf is a whole message `content`, so a flagged tool message is replaced whole.
  If the finding cannot be located (bound reached, a locating call returns `null`, or a
  flagged group reproduces in neither half) the prompt is refused (`dlp_policy_violation`)
  / the result withheld with `findingTypes` naming the type: never passed. A credential
  finding that only appears while locating also blocks. No proto change was needed.
- E-mail addresses / UPNs → **returned unchanged**. The agent needs the UPN to act, and the
  data goes only to the customer's own model deployment. Before this decision any real
  manar-ai finding (an e-mail is deterministic HIGH) replaced the whole result, so the SOC
  agent could not read an incident (docs/reports/FIRST-AGENT-RUN-2026-09-25.md, workspace
  repo).
- Each withhold or in-place redaction records `dlp.result_redacted` with `mode`
  (`withheld` / `redacted_in_place`), per-type floor match counts, `advisoryRedactedCounts`
  (leaves replaced per manar-ai type), `unlocatedTypes`, and the blocking manar-ai finding
  types/previews. Never the values. The proxy's `llm.request` carries
  `dlp.advisoryRedactedCounts` the same way.
- manar-ai unavailable (`null`) on this path: unchanged, the manar-ai check is skipped and
  does not block (unlike the proxy, where `null` is a 503). The tool call has already
  happened; the result goes to the agent, whose next LLM call passes through the proxy, where
  `null` blocks. The deterministic floor does not depend on manar-ai and now applies to
  results whether or not manar-ai answers (before this, a `null` returned the result
  untouched).

None of this is on the authorization decision path. `decision-path-dependencies.spec.ts`
now also fails if anything under `src/agent-runtime/` (other than the zod config schema)
or any `fetch(` call becomes reachable from `authorization.service.ts`.

**Payload retention.** The spec's default is to retain full prompts. This ADR retains a
hash and metadata only, for three reasons: the pilot customer's data is government /
semi-government (Decisions.md, round 3); prompts carry tool results, i.e. the customer's
Entra and Defender data, which would then sit in our audit store; and a retention and
access model for that content does not exist yet. The SHA-256 lets an auditor match a
prompt the customer holds to a recorded call. Revisit when there is a per-tenant setting
and a reviewed store for it.

## Alternatives considered

- **Proxy in manar-ai.** It already talks to Ollama/vLLM for its own analyses. Rejected:
  the agent's only egress is manar-api (spec §5.2 hard requirement), task identity and
  budget live here, and manar-ai must stay off anything that decides.
- **Keep DLP only in manar-ai.** Rejected by S6/S29: a `null` fails open and manar-ai's
  patterns cover none of the Azure/Entra credential shapes or UAE PII.
- **Block on every HIGH verdict from manar-ai**, as the tool path does. Rejected for this
  path: when manar-ai's own model is down, an e-mail address alone becomes HIGH (S7), so
  every SOC prompt with a UPN would be blocked by an AI outage.
- **Budget in PostgreSQL** (a `Task` column). Durable across Redis restarts, but needs a
  tenant migration on a branch other agents are migrating too. Redis is already the limits
  store and fails closed here.
- **Streaming.** Not needed by the V1 agent. Rejected for now; `stream: true` is a 400.
- **Portable capability token as the proxy credential.** Deferred with ADR-0003; the mTLS
  identity plus `X-Manar-Task-Id` is checked against the task on every call.

## Consequences

- The agent needs only its Manar-issued certificate and key; no model key, no Microsoft
  client, no Graph credential.
- A manar-ai outage stops the agent's reasoning (503) but not its reads of its own
  approvals. This is the intended trade (fail closed on content egress).
- Budget checks are check-then-add: concurrent calls on one task can overshoot by one call
  each. A Redis flush resets budgets (they are not in PostgreSQL).
- A task whose `maxExecutions` is reached can no longer call the model either (the
  liveness check is shared).
- Found while seeding: a task's grants are the cross-join of its actions and selectors per
  tool, and task creation writes all tuples in one OpenFGA call limited to 100 writes
  (about 30 grants). A larger task fails with a 500 at creation. Not fixed here.

## Enforcement-label impact

None changes by this ADR alone. The LLM proxy, manifest and MCP server are prerequisites
for the Phase 1 `governed` derivation (the agent deployed in the box), which is decided at
Gate 1.

## Agent contract

Everything below is on the mTLS listener (`https://<manar-api>:3443`, `AGENT_MTLS_PORT`),
except enrollment, which is on the human HTTP listener (`:3000`, `PORT`). Every agent
request presents the Manar-issued client certificate and key and trusts the Manar CA chain
returned at enrollment. Common failures on any `/agent/v1/*` route:

| Status                | Body                                                                                                                   | Meaning                                                    |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| TLS handshake refused | —                                                                                                                      | no client certificate                                      |
| 401                   | `{"statusCode":401,"message":"Agent is not active","error":"Unauthorized"}` (message varies)                           | certificate unknown/revoked, agent not ACTIVE              |
| 403                   | `{"decision":"DENY","reason":"<reason>"}`                                                                              | a governance decision; do not retry                        |
| 429                   | Nest throttler body                                                                                                    | per-agent rate limit (default 120 requests/min)            |
| 503                   | `{"statusCode":503,"error":"Service Unavailable","reason":"enforcement_dependency_unavailable","dependency":"<name>"}` | a control could not be evaluated; retry later with backoff |

Task-gate reasons (proxy, manifest, MCP `tools/list`): `task_not_found`,
`not_assigned_agent`, `task_status_<status>` (e.g. `task_status_revoked`),
`task_outside_time_window`, `task_execution_limit_reached`, `ancestor_<any of these>`,
`platform_kill_switch_active`, `tenant_kill_switch_active`, `agent_kill_switch_active`,
`agent_group_kill_switch_active`, `ai_system_suspended`, `ai_system_retired`.

### 0. Enrollment (once per pod start)

An operator (TENANT_OWNER or SECURITY_ADMIN) mints a one-time token (15-minute TTL, hashed
at rest) and hands it to the pod out of band:

```bash
# Human listener, Keycloak bearer of a TENANT_OWNER / SECURITY_ADMIN user.
curl -s -X POST "$MANAR_API/agents/$AGENT_ID/enrollment-tokens" -H "Authorization: Bearer $OWNER_TOKEN"
# -> 201 {"token":"<tenantSlug>:<agentSlug>:<random>","expiresAt":"2026-09-25T16:30:00.000Z"}
```

For the demo tenant, `pnpm manar demo:seed --microsoft-fixture-url <fixture>` creates the
agent `manar-soc-agent` (unenrolled) and its task, and writes `agentId`, `agentSlug` and
`taskId` under `socLlmAgent` in `.manar-demo/tenant-credentials.json`, next to the realm,
client id/secret and user password needed to get `$OWNER_TOKEN` for `demo-owner` with a
Keycloak password grant (see `docs/demo.md`).

The agent generates an ECDSA P-256 key locally and a PKCS#10 CSR whose subject is
`CN=agent://<tenantSlug>/<agentSlug>` and whose only SAN is the URI
`agent://<tenantSlug>/<agentSlug>` (both parts are the first two `:`-separated fields of
the token), then:

```http
POST /agents/enroll            (human listener, no auth header; the token authenticates)
Content-Type: application/json

{"token":"vax-security-ops-demo:manar-soc-agent:3q2...","csr":"-----BEGIN CERTIFICATE REQUEST-----\n..."}
```

`201 {"certificate":"-----BEGIN CERTIFICATE-----...","caChain":"-----BEGIN CERTIFICATE-----...","serialNumber":"4A1F...","notBefore":"...","notAfter":"..."}`.
Any token problem is `401 {"statusCode":401,"message":"Invalid enrollment token","error":"Unauthorized"}`;
a bad CSR is 400. The reference implementation is `packages/sdk-node/src/csr.ts`.

### A. LLM proxy

```http
POST /agent/v1/llm/chat/completions
X-Manar-Task-Id: 5d0c...-task-uuid
Content-Type: application/json

{
  "messages": [
    {"role": "system", "content": "You are a SOC analyst agent."},
    {"role": "user", "content": "Investigate Defender incident 4201."}
  ],
  "tools": [{"type": "function", "function": {"name": "microsoft-graph__security.incident.get",
             "description": "...", "parameters": {"type": "object", "properties": {"resource": {"type": "string"}, "params": {"type": "object"}}, "required": ["resource"]}}}],
  "tool_choice": "auto",
  "temperature": 0,
  "max_tokens": 2048
}
```

Accepted fields: `messages` (required, ≥ 1, each with `role`; other message fields such as
`content`, `tool_calls`, `tool_call_id`, `name` pass through), `tools`, `tool_choice`,
`temperature` (0–2), `max_tokens`, `reasoning_effort` (`none`, `minimal`, `low`, `medium`, `high`;
`none` is sent to Azure OpenAI as `minimal`; added 2026-10-09 for the watcher, ADR-0009),
`model` (ignored), `stream` (`false` or absent). Other fields are dropped. Body limit is Fastify's default 1 MiB.

`200`, headers `x-manar-task-id: <taskId>` and `x-manar-request-id: <correlation id>`, body
is the upstream's OpenAI chat completion as returned (Ollama may add `reasoning` on the
message):

```json
{
  "id": "chatcmpl-772",
  "object": "chat.completion",
  "created": 1790352828,
  "model": "qwen3.5:9b",
  "choices": [
    {
      "index": 0,
      "finish_reason": "tool_calls",
      "message": {
        "role": "assistant",
        "content": "",
        "tool_calls": [
          {
            "id": "call_9vxm23e9",
            "type": "function",
            "function": {
              "name": "microsoft-graph__security.incident.get",
              "arguments": "{\"resource\":\"4201\",\"params\":{\"expandAlerts\":false}}"
            }
          }
        ]
      }
    }
  ],
  "usage": {
    "prompt_tokens": 941,
    "completion_tokens": 264,
    "total_tokens": 1205
  }
}
```

Errors:

| Status | Body                                                                                      | When                                                                                           |
| ------ | ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| 400    | `{"statusCode":400,"message":"X-Manar-Task-Id header is required","error":"Bad Request"}` | header missing                                                                                 |
| 400    | `{"statusCode":400,"message":"Invalid request body: ...","error":"Bad Request"}`          | schema, or `stream: true`                                                                      |
| 403    | `{"decision":"DENY","reason":"<task-gate reason>"}`                                       | see list above                                                                                 |
| 403    | `{"decision":"DENY","reason":"dlp_policy_violation"}`                                     | a credential in the prompt (floor or manar-ai); the prompt was not sent                        |
| 429    | `{"decision":"DENY","reason":"llm_budget_exhausted"}`                                     | task token budget used up; final for this task                                                 |
| 502    | `{"reason":"llm_upstream_unavailable"}`                                                   | model provider down, timed out (`LLM_UPSTREAM_TIMEOUT_MS`, default 180 s) or non-2xx           |
| 503    | `{..."reason":"enforcement_dependency_unavailable","dependency":"dlp-advisory"}`          | manar-ai did not answer (also `tenant-db`, `kill-switch-store`, `limits-store`, `audit-store`) |

UAE PII in the prompt is not an error: it is replaced before sending, and the model sees
the placeholder.

### B. Tool manifest

```http
GET /agent/v1/tasks/{taskId}/tool-manifest
```

```json
{
  "taskId": "5d0c...",
  "tools": [
    {
      "name": "microsoft-defender__defender.machine.isolate",
      "toolId": "microsoft-defender",
      "actionId": "defender.machine.isolate",
      "description": "Isolate a device from the network (Full or Selective). Reversible with defender.machine.unisolate.",
      "inputSchema": {
        "type": "object",
        "additionalProperties": false,
        "required": ["comment"],
        "properties": {
          "comment": { "type": "string", "minLength": 1, "maxLength": 1000 },
          "isolationType": { "enum": ["Full", "Selective"] }
        }
      },
      "mutating": true,
      "destructive": true,
      "resourceSelector": ["4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70"]
    }
  ]
}
```

`name` is `<toolId>__<actionId>`; split on the **first** `__`. `resourceSelector` is an
**array**: every resource pattern the grant set allows for that action (`"*"` = any).
`inputSchema` is the action's JSON Schema for `params` (not wrapped). Tools are sorted by
`name`. Errors: the task-gate 403s and the 503 above.

Tool names contain `.` (e.g. `security.incident.get`). Ollama accepts that (verified with
`qwen3.5:9b`), but the OpenAI and Azure OpenAI APIs restrict function names to
`^[a-zA-Z0-9_-]{1,64}$`. With `LLM_PROVIDER=azure_openai` the agent must map names to a safe
form for the model (e.g. `.` → `-`, or an index) and keep a lookup back to the manifest
name; manar-api forwards `tools` as given.

### C. Governed MCP server

`POST /agent/v1/tasks/{taskId}/mcp`, JSON-RPC 2.0 over MCP Streamable HTTP, stateless (no
`Mcp-Session-Id`), JSON responses. Send `Content-Type: application/json` and
`Accept: application/json, text/event-stream`. `GET` and `DELETE` on the same path answer
`405`. `initialize` returns `serverInfo.name = "manar-governed-mcp"` and the `tools`
capability.

`tools/list` result, one entry per manifest tool:

```json
{
  "tools": [
    {
      "name": "microsoft-graph__security.incident.get",
      "description": "Read one Defender XDR incident, optionally with its alerts.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "resource": {
            "type": "string",
            "description": "Target resource id. Allowed: 4201"
          },
          "params": {
            "type": "object",
            "additionalProperties": false,
            "properties": { "expandAlerts": { "type": "boolean" } }
          }
        },
        "required": ["resource"]
      },
      "annotations": { "readOnlyHint": true, "destructiveHint": false }
    }
  ]
}
```

A task-gate refusal on `tools/list` is a JSON-RPC error whose `data` is stable:
`{"jsonrpc":"2.0","id":2,"error":{"code":-32600,"message":"MCP error -32600: DENY: not_assigned_agent","data":{"status":"DENIED","reason":"not_assigned_agent"}}}`.

`tools/call` with `{"name":"<toolId>__<actionId>","arguments":{"resource":"4201","params":{"expandAlerts":true}}}`
(`params` optional, defaults to `{}`) runs the same pipeline as `POST /agent/v1/tools/invoke`.
`content` is always one text item holding `JSON.stringify(structuredContent)`.

- Executed (ALLOW, or the tool ran and failed): `isError: false`,
  `structuredContent = {"success":true,"data":{...tool result...},"status":"EXECUTED","outcome":"SUCCESS"}`.
  A failed call is `{"success":false,"errorMessage":"HTTP 404","status":"EXECUTED","outcome":"FAILURE"}`;
  a mutation whose answer was lost is `{"success":false,"errorMessage":"...","outcomeUnknown":true,"status":"EXECUTED","outcome":"UNKNOWN"}`:
  it may have happened, **do not retry it**. A result redacted by DLP or flagged for prompt
  injection comes back exactly as the pipeline returned it.
- Approval required: `isError: false`,
  `structuredContent = {"status":"PENDING","approvalId":"0b6f...","reason":"policy_requires_approval","riskScore":62,"nextStep":"..."}`.
  Nothing was sent to Microsoft. Calling the same tool again with the same arguments while a
  person has not decided returns the same `approvalId` (no second request), unless the fresh
  decision scores higher or changed policy version or reason: then the old request is expired
  and a new `approvalId` comes back. An MCP client
  finishes the action over MCP only (ADR-0007):
  1. `tools/call` `manar_approval_status` with `{"approvalId":"0b6f...","waitSeconds":25}`
     (`waitSeconds` 0–50, default 25; it waits while `PENDING`; call it again if still
     `PENDING`). Result:
     `{"approvalId":"0b6f...","status":"PENDING|APPROVED|DENIED|EXPIRED","tool":"<toolId>__<actionId>","resource":"...","nextStep":"..."}`,
     plus `grantExpiresAt` when an approved grant is still usable. An approval of another agent
     or another task is `{"status":"DENIED","reason":"approval_not_found"}`. It never returns a
     grant token.
  2. Once `APPROVED`, call the same tool again with **exactly** the same `resource` and
     `params`. Manar finds the grant, re-runs the whole decision and runs it once (`EXECUTED`).
     A kill switch or policy change since approval returns `DENIED` with its reason. A second
     identical call after that asks for a new approval.

  REST clients use section D instead.

- Denied: `isError: true`, `structuredContent = {"status":"DENIED","reason":"<reason>"}`.
  Reasons: the task-gate reasons, `forbidden_action`, `not_authorized` (outside the grant
  set; deliberately generic), `policy_denied`, `policy_evaluation_failed`,
  `task_execution_limit_reached`, `dlp_policy_violation`, `tool_not_found`,
  `tool_disabled`, `unknown_tool` (name has no `__`), `invalid_arguments` (e.g. no
  `resource`), `enforcement_dependency_unavailable` (retryable), and at redemption the
  section D grant reasons and kill-switch reasons.

### D. Approval over REST: poll, then redeem

MCP clients do not need this section (see C and ADR-0007).

Poll `GET /agent/v1/approvals/{approvalId}` (every few seconds; mind the 120/min limit):

```json
{
  "id": "0b6f...",
  "status": "PENDING",
  "taskId": "5d0c...",
  "toolId": "microsoft-defender",
  "actionId": "defender.machine.isolate",
  "resource": "4d5e...6f70",
  "riskScore": 62,
  "requestedAt": "2026-09-25T16:04:10.000Z",
  "expiresAt": "2026-09-25T16:34:10.000Z"
}
```

`status` is `PENDING`, `APPROVED`, `DENIED` or `EXPIRED` (a request waits up to
`APPROVAL_REQUEST_TTL_MS`, default 30 minutes). **The grant token is returned here**, only
when `status` is `APPROVED` and the grant is still usable, as two extra fields:

```json
{
  "id": "0b6f...",
  "status": "APPROVED",
  "...": "as above",
  "grantToken": "<opaque signed token>",
  "grantExpiresAt": "2026-09-25T16:10:12.000Z"
}
```

`APPROVED` without `grantToken` means the grant was already used, revoked or expired. An
unknown id, or one belonging to another agent, is `404`. `DENIED` and `EXPIRED` are final.

Redeem once, before `grantExpiresAt` (grant TTL `APPROVAL_GRANT_TTL_MS`, default 5 minutes),
with **exactly** the `taskId`, `toolId`, `actionId`, `resource` and `params` of the original
request (the grant is bound to their hash; if the MCP call omitted `params`, send `{}`):

```http
POST /agent/v1/tools/invoke
Content-Type: application/json

{"taskId":"5d0c...","toolId":"microsoft-defender","actionId":"defender.machine.isolate",
 "resource":"4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70",
 "params":{"comment":"Credential dumping on fx-ws-042 (fixture incident 4201)"},
 "grantToken":"<grantToken>"}
```

`200` with the tool result, same shape as `structuredContent` above without
`status`/`outcome`: `{"success":true,"data":{"type":"Isolate","machineId":"4d5e...",...}}`.
A rejected grant is `403 {"decision":"DENY","reason":"grant_invalid|grant_mismatch|grant_not_found|grant_revoked|grant_already_consumed|grant_expired|task_not_found|agent_not_active|<kill-switch reason>"}`;
kill switches and task state are re-checked at redemption. The same endpoint without
`grantToken` is the REST twin of `tools/call`: `200` tool result, `202`
`{"status":"PENDING","reason":"...","riskScore":62,"approvalId":"..."}`, or `403`
`{"decision":"DENY","reason":"..."}` (`404` unknown tool/action, `409` tool disabled).

### Configuration (manar-api side)

| Variable                                                    | Default                     |                                          |
| ----------------------------------------------------------- | --------------------------- | ---------------------------------------- |
| `LLM_PROVIDER`                                              | `ollama`                    | or `azure_openai`                        |
| `LLM_OLLAMA_BASE_URL`                                       | `http://localhost:11434/v1` |                                          |
| `LLM_MODEL`                                                 | `qwen3.5:9b`                | Ollama model                             |
| `LLM_AZURE_OPENAI_ENDPOINT` / `LLM_AZURE_OPENAI_DEPLOYMENT` | —                           | required for `azure_openai`              |
| `LLM_AZURE_OPENAI_API_VERSION`                              | `2024-10-21`                |                                          |
| `AZURE_OPENAI_API_KEY`                                      | —                           | environment only, never on disk          |
| `LLM_TASK_TOKEN_BUDGET`                                     | `200000`                    | per task, upstream-reported total tokens |
| `LLM_UPSTREAM_TIMEOUT_MS`                                   | `180000`                    |                                          |
