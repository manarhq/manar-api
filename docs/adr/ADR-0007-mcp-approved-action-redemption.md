# ADR-0007 — An MCP client completes an approved action by calling the same tool again

- **Status:** ACCEPTED
- **Date:** 2026-10-08
- **Phase:** 1 (MCP gateway for third-party agents, roadmap week 12–18 Oct)
- **Deciders:** engineering judgement

## Context

The governed MCP server (`POST /agent/v1/tasks/:taskId/mcp`, `src/agent-runtime/agent-runtime.controller.ts`)
runs `tools/call` through `ToolInvocationService`, the same pipeline as `POST /agent/v1/tools/invoke`.
When the decision is APPROVAL_REQUIRED it answers `{ status: 'PENDING', approvalId }`. After a
person approves, the REST door finishes the action with `GET /agent/v1/approvals/:id` (which hands
out a signed grant token) and a retry carrying `grantToken`. The MCP door had no way to carry that
token: `tools/call` arguments are the tool's own `resource` and `params`, and a generic MCP client
(Claude Code, Copilot Studio, Foundry) will not put a Manar token anywhere. The 8 Oct live demo
worked around it with a REST call inside the stdio-to-mTLS bridge (`~/manar-demo/manar-mcp-bridge.py`),
so an "MCP-only" agent was not MCP-only.

ADR-0006 still holds: a grant is single use, bound to agent, task, tool, action, resource and the
parameter hash, and redemption re-runs the whole decision and writes a `Decision`.

## Decision

1. **Server-side redemption on the MCP door.** When `tools/call` arrives on the MCP channel with no
   grant token, `ToolInvocationService` asks `GrantService.findRedeemableGrantToken` for the newest
   unconsumed, unrevoked, unexpired `AuthorizationGrant` whose agent (from the mTLS identity), task
   (from the URL), tool, action, resource and parameter hash equal this call's. If one exists the
   server signs its token and takes the existing redemption path unchanged: `verifyGrant`, then
   `authorizeRedemption` (kill switches, AI-system lifecycle, assignment, task liveness, forbidden
   actions, OpenFGA, current policy), which consumes the grant in the same transaction as its
   `Decision` (stage `GRANT_REDEMPTION`, channel `MCP`). The token never leaves the server.
2. **No duplicate approvals while a person decides.** On APPROVAL_REQUIRED the MCP door first looks
   for an unexpired PENDING `ApprovalRequest` for the same agent, task, tool, action, resource and
   parameters (`ApprovalRequestService.findPendingMatch`). If one exists it answers with that
   `approvalId` instead of opening a second request. A `Decision` (APPROVAL_REQUIRED) is still
   written for the call.
3. **A read-only status tool.** Every MCP session lists `manar_approval_status { approvalId,
waitSeconds? }`. It runs the same task-access gate as `tools/list` (kill switches, task assigned
   to this agent, task live), then returns the status of an approval that belongs to this agent
   **and** this session's task; anything else is `approval_not_found`. It waits up to `waitSeconds`
   (default 60, max 120) while the status is PENDING, polling PostgreSQL. It never returns a grant
   token and never executes anything.
4. **Results say what happened and what to do next.** PENDING carries `approvalId` and `nextStep`:
   nothing ran; wait with `manar_approval_status`; once APPROVED call the same tool again with
   exactly the same arguments. The status tool's `nextStep` changes with the status (still waiting,
   call again now, refused, expired, already used).
5. **The REST door is unchanged.** It keeps the explicit `grantToken` retry and opens a new
   approval on every APPROVAL_REQUIRED, so `scripts/demo-agent.ts`, `packages/sdk-node` and the
   rehearsed fallback behave exactly as before.
6. **Fail closed.** A grant-store failure during the lookup, or an approval-store failure during the
   pending lookup, is a 503 `enforcement_dependency_unavailable`; nothing executes.

Session binding (Addendum G15/G16) is by construction: the server is stateless and the task is the
URL path segment, checked against the mTLS identity on every request. A session cannot address
another task's tools, approvals or grants, and without a valid agent certificate no MCP method
answers (TLS refuses the handshake; a revoked agent gets 401 from `AgentMtlsGuard`).

## Alternatives considered

- **(b) Agent passes the grant in MCP `_meta`.** Needs a Manar-aware client: the model or a bridge
  must fetch the token over REST and inject `_meta`. That is the workaround this ADR removes, and it
  hands a bearer grant to the agent process for no gain, since the server already knows which grant
  matches.
- **(c) Status tool only, then a retry that still needs the token.** Same problem as (b) for the
  retry. Kept as the waiting half of this decision (point 3), not as the redemption mechanism.
- **Block `tools/call` until a person decides.** Holds an HTTP request for minutes, hits client and
  proxy timeouts, and gives the agent nothing to tell the user meanwhile. The bounded status wait
  covers the need.
- **Auto-redeem on the REST door too.** Changes a tested contract the SDK and the rehearsed
  fallback depend on, and REST callers can already carry the token. Can be revisited.
- **Do nothing.** Every outside MCP agent needs a custom bridge to finish an approved action.

## Consequences

- Any MCP client finishes an approved action with no Manar-specific code: call, wait, call again.
- A repeated identical call after approval runs the action. That is the approved intent (same agent,
  task, tool, action, resource and parameter hash), and it runs once: the second identical call
  after consumption finds no grant and asks for a new approval.
- Two concurrent identical calls after approval: both find the grant, the conditional consume lets
  one win, the other is a recorded DENY `grant_already_consumed`.
- If redemption is refused (for example a kill switch engaged after approval), the grant stays
  unconsumed until it expires (`APPROVAL_GRANT_TTL_MS`, 5 minutes), as on the REST door; a retry
  after the switch is released re-decides from scratch.
- Each status poll is one indexed lookup by primary key per second at most, and no `Decision` row
  (it is not an action request). The pending-match lookup scans the task's approvals for the tool
  and resource without a dedicated index; acceptable at today's volumes.
- Rollback: revert the commits. No migration.

## Enforcement-label impact

None changes label. The MCP door was already `governed` for ALLOW and DENY; this makes approved
actions completable on it without leaving MCP, under the same single-use, parameter-bound,
re-decided grant. Evidence: `src/tools/tool-invocation.service.spec.ts` (MCP door block),
`src/approvals/grant.service.mcp-lookup.spec.ts`, `test/agent-runtime.e2e-spec.ts` (governed MCP
server: approved action over MCP only, negative cases, G15, G16).
