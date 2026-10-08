# ADR-0008 - A read-only console assistant that reads as the signed-in human

- **Status:** PROPOSED
- **Date:** 2026-10-09
- **Phase:** hackathon demo, 21 October 2026 (founder request, approved)
- **Deciders:** Mohamed (feature and safety rules); engineering judgement (design)

## Context

Operators ask the same questions every shift: why was this action denied, what did this agent
do today, which approvals are waiting and which is riskiest, what does this rule mean, how do I
add an agent. The answers already exist behind the console's read routes (`GET /audit`,
`GET /approvals`, `GET /approvals/:id`, `GET /agents`, `GET /policies[/:id]`,
`GET /incidents/:id`), spread across pages.

An assistant that answers them is itself an AI with access to tenant data, so it has to follow
Manar's own rules: it must not act, must not see more than the person asking, must not sit on the
decision path, must treat agent-written data as untrusted, and must not leak secrets or PII to a
model. The model is reached the same way agents reach one: `LlmUpstreamClient`
(`src/agent-runtime/llm-upstream.client.ts`, ADR-0002), Azure OpenAI when `LLM_PROVIDER` is
`azure_openai` and configured, otherwise Ollama.

There is no human-facing decision read endpoint on `main` yet (the `Decision` table is in MR !9),
so decisions are read from the audit log's `authorization.*` events.

## Decision

1. **Module.** `src/assistant/` on the human HTTP app only: `POST /assistant/chat`
   (JwtAuthGuard, any role of the tenant), plain JSON, not streamed.
2. **Fixed tool set** (`assistant.tools.ts`), all reads or static text: `search_decisions`,
   `get_decision`, `get_audit_event`, `list_pending_approvals`, `get_approval`,
   `get_agent_activity`, `get_policy_rule`, `get_incident`, `explain_reason_code`,
   `help_lookup` (curated EN/AR how-to, `assistant.knowledge.ts`), and `prepare_for_human`,
   which only returns a suggestion (open a record or page, open an approval with the Approve or
   Deny button highlighted, show a draft policy rule to copy). It never submits anything.
3. **Read as the human.** A tool's only access to tenant data is `ToolContext.read(path)`, which
   `AssistantReader` serves with Fastify `inject`: an in-process `GET` on manar-api's own routes,
   carrying the caller's own `Authorization` header and nothing else. The route's JwtAuthGuard,
   RolesGuard and issuer-based tenant resolution therefore decide what the assistant may see,
   exactly as for the console. There is no service account. `read` refuses any path outside
   `READ_PATHS` (seven GET patterns), ids are UUID-validated, query values are URL-encoded and
   tool argument schemas are strict, so neither the model nor injected text can widen a read.
   A 401/403 comes back to the model as `not_permitted_for_your_role` and is never retried.
4. **Untrusted data.** Every tool result goes to the model inside a `<data tool="...">` block,
   with `<` escaped so the data cannot close the block. The system prompt says the block is data,
   never instructions. Unknown tool names and invalid arguments are refused and reported back;
   the tool list is the same on every turn. The worst case left is a wrong answer, so every
   answer carries the sources it was built from (links to the audit event, approval, agent,
   policy or incident), and citations that point at nothing read are dropped.
5. **DLP before the model.** The operator's messages and every tool result go through
   `classifyDlp` (the same classification the LLM proxy and tool results use): UAE PII redacted
   in place, manar-ai generic findings redacted per leaf, a credential-shaped value withholds the
   whole tool result (or refuses the question). If manar-ai is unavailable the deterministic floor
   still applies, as on the tool-result path.
6. **No content in logs or audit.** One `assistant.request` audit event per question with
   metadata only (outcome, tool names, counts, rounds, latency, a SHA-256 of the messages). No
   question, answer or tool output is logged or stored.
7. **Conversation stays in the browser.** The console keeps it in `sessionStorage` and sends the
   history with each question; manar-api stores nothing. No retention to manage.
8. **Limits.** 12 questions per user per minute (Redis, key `tenant:user`), at most 5 model turns
   and 4 tool calls per turn. No model answering returns `{ available: false }` and the console
   says "Assistant unavailable".
9. **Not on the decision path.** `decision-path-dependencies.spec.ts` fails if anything under
   `src/assistant/` becomes reachable from `authorization.service.ts`.

## Alternatives considered

- **Call the services directly with the `AuthContext`.** Fewer hops, but every tool would
  re-implement the role gates the controllers already declare, and the two would drift. Going
  through the routes makes the console's RBAC the assistant's RBAC by construction.
- **A service account with tenant-wide read.** Simpler, and exactly the elevation the founder
  ruled out: a READ_ONLY user could read the audit log through the assistant.
- **Store conversations server side.** Useful for hand-over between shifts, but it means a new
  tenant table holding free text and a retention job. Not needed for 21 October.
- **Let the model call write routes behind a confirmation.** Rejected by the founder's rules:
  any action goes through the normal UI and its checks.
- **manar-ai `InvestigateAudit`.** Covers audit questions only and does no tool calling.

## Consequences

- Each tool read is an extra in-process HTTP request (JWT verified again, counted against the
  tenant's human rate limit). Bounded by the per-user limit and the 4x5 call cap.
- Answers are only as good as the model. On local `qwen3.5:9b` tool choice and wording vary;
  gpt-5-mini is expected to do better. The guarantees above do not depend on the model.
- `LlmUpstreamClient` gained an optional pass-through `reasoning_effort` field; the assistant sets
  `none` for Ollama only.
- When MR !9 lands, `search_decisions`/`get_decision` can move from audit events to the
  `Decision` record once it has a human read route with the same RBAC.
- Rollback: remove `AssistantModule` from `app.module.ts`. No migration.

## Enforcement-label impact

None. The assistant decides nothing and changes nothing; it reads what the caller can already read.
