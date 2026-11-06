# AI cost telemetry and the staff API (performance program, decisions 7 to 10)

## What is recorded

Every model call that costs us tokens adds one update to a **daily rollup** in the control database
(`ai_usage_daily`, one row per UTC day, workspace, feature, provider and model):

| Column                                        | Meaning                                                                                                                                                                                                                       |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `calls`, `errors`                             | Calls and those that ended in an error or with no answer (`unavailable`). A call the person stopped counts as a call, not an error.                                                                                           |
| `inputTokens`, `outputTokens`                 | From the provider's usage report. The assistant estimates (4 characters per token) only when the provider reports none.                                                                                                       |
| `costMicros`, `priceVersion`, `unpricedCalls` | Our price table (`src/ai-telemetry/ai-prices.ts`, USD per 1M tokens per model, versioned) times the tokens. A model with no price costs 0 and is counted in `unpricedCalls`. Self-hosted providers (`ollama`, `vllm`) cost 0. |
| `latencyMsSum`, `latencyBuckets`              | Request to last token. Buckets are `AI_LATENCY_BUCKETS_MS`; p50 and p95 are interpolated from them.                                                                                                                           |

Features: `assistant`, `incident_summary`, `audit_investigate`, `policy_suggest`. Never stored, logged or
labelled: prompts, answers, tool output, people. Prometheus gets totals and histograms by **feature and
model only** (`manar_ai_calls_total`, `manar_ai_tokens_total`, `manar_ai_cost_usd_total`,
`manar_ai_call_duration_seconds`, `manar_ai_first_token_seconds`), never a workspace label. manar-ai adds
`ai_llm_*` and `ai_stream_*` series of its own.

The hot-lane advisories (risk, prompt injection, DLP) are not recorded yet: manar-ai does not return
usage for them, and they are not part of this program.

To change a price add a new `version` with the new numbers; history keeps the version it was priced with.
Reconcile the month's rollup against the Azure bill monthly (decision 9).

## Staff API (for the Desk AI page)

Platform token (client-credentials, `PLATFORM_API_ISSUER`) with `PLATFORM_API_ROLE` **and** the staff
Owner realm role `PLATFORM_OWNER_ROLE` (default `manar-platform-owner`). Without the Owner role: 403.
Desk should call with a token that carries both roles (the signed-in Owner's token, or a dedicated
service account holding both); Desk's own Owner check remains the first gate (decision 8).

`GET /platform/v1/ai-usage?from=YYYY-MM-DD&to=YYYY-MM-DD&groupBy=feature,model&workspaceId=&feature=&model=`

- `groupBy`: comma list of `workspace`, `feature`, `model`, `day` (default `feature,model`). Window at most
  93 days, default the last 30. `from`/`to` are UTC dates, inclusive.
- Response: `{ priceVersion, from, to, groupBy, rows[] }`; each row has the group keys
  (`workspaceId`, `workspaceName`, `feature`, `model`, `day` as requested) and
  `calls, errors, errorRate, inputTokens, outputTokens, costUsd, unpricedCalls, p50Ms, p95Ms`.
  Rows are sorted by cost, then calls.

`GET /platform/v1/ai-usage/top-workspaces?limit=10` (1 to 100): the costliest workspaces today (UTC), same
row shape grouped by workspace. `{ priceVersion, day, rows[] }`.

`GET /platform/v1/ai-usage/spikes`: the spend-spike signal (decision 7). `{ spikes: [{ tenantId, todayUsd,
baselineUsd, ratio }] }`. A workspace spikes when today's cost is at least 3 times the median of its
daily cost over the previous 7 days (days with no spend are not counted) and at least 5 USD; with no
history, passing the 5 USD floor alone is a spike. `tenantId: null` is the platform total against its own
history. Desk polls this and raises the alert; nothing here pages anyone by itself.

`GET /platform/v1/ai-usage/prices`: the price table in force.

## Customer usage (decision 10)

`GET /billing/usage/daily?days=30` (1 to 90; roles `TENANT_OWNER`, `SECURITY_ADMIN`, like
`GET /billing/usage`): the workspace's own AI actions per UTC day, split into `fromAllowance` and
`fromCredits` (1 credit = 1 AI action), from the same `usage_events` rows the meter writes, plus the month
figures from `GET /billing/usage`. A day's numbers add up to the month's `allowance.ai.used` and
`creditsSpent` by construction. The console page is Settings, AI usage.

## Streaming and background jobs

SSE endpoints (`text/event-stream`, `Cache-Control: no-cache, no-transform`, a `: heartbeat` comment every
10 s):

| Endpoint                                                             | Events                                                                  |
| -------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `POST /assistant/chat/stream`                                        | `token` `{t}`, `tool` `{names}` (drop the text so far), `done`, `error` |
| `POST /incidents/summarize/stream`, `POST /audit/investigate/stream` | `delta` `{t}` (redacted), `done`, `error`                               |
| `GET /policies/suggest/jobs/:id/events`                              | `progress`, `done`, `reconnect` (after about 55 s: open it again)       |

Suggest Policy is a background job (`POST /policies/suggest/jobs` answers 202; `GET`/`DELETE
/policies/suggest/jobs/:id`), run by a Temporal workflow in the worker. Its state is in Valkey for 24 hours
(`manar:aijob:<tenant>:<id>`; the prompt is kept for at most an hour and deleted when the worker takes it);
the durable result is the DRAFT policy version. A job whose worker went silent for 90 s reads as `failed`
with `error: "stalled"` and its AI action is given back. A watcher that loses its stream (a proxy cut it at
100 s) opens it again and loses nothing, because the stream is a view of the stored state.

Timeouts: one assistant model round is bounded by `ASSISTANT_LLM_ROUND_TIMEOUT_MS` (45 s) for the first
token and `LLM_STREAM_IDLE_MS` (20 s) between chunks; the agents' LLM proxy keeps `LLM_UPSTREAM_TIMEOUT_MS`
(180 s). Background jobs are bounded by `AI_JOB_TIMEOUT_MS` (10 min).
