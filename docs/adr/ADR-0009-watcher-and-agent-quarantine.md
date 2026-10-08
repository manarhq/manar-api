# ADR-0009: The watcher may quarantine agents; only a human releases

- **Status:** PROPOSED (lead review; depends on MR !9, ADR-0006)
- **Date:** 2026-10-09
- **Phase:** hackathon demo (21 Oct 2026); first slice of spec Phase 7 (quarantine)
- **Deciders:** founder brief (9 Oct: "AI may tighten on its own; loosening always needs a
  human"), engineering judgement for the mechanism

## Context

The founder wants an AI agent that watches the other agents of a tenant and stops one that
misbehaves, itself governed by Manar. Workspace `CLAUDE.md` §4.1: authorization stays
deterministic; an LLM, heuristic or anomaly score may only add restriction. So the safety rule
must be enforced by manar-api, not by the watcher's prompt: the watcher can tighten (quarantine)
without a human; it can never loosen (release a quarantine, turn off a kill switch, change
policy, grant tools, approve, alter or delete records).

What existed: kill switches (`src/kill-switches/kill-switch.service.ts`, `checkAll`) read on
every decision by `AuthorizationService.evaluate` (first attempt and grant redemption) and by
`AgentTaskAccessService` (LLM proxy, tool manifest, MCP). An AGENT-scope kill switch already
denies everything. But `KillSwitch.activatedBy` is a foreign key to `UserProfile` (a human), its
deny reason is `agent_kill_switch_active`, it has no place for evidence or an explanation, and a
human deactivating it writes `kill_switch.deactivated`, not a quarantine release. Spec §11 (Phase 7) describes quarantine as capturing mutations rather than denying them; the 9 Oct brief asks for
a simpler, fail-closed deny for the demo.

## Decision

1. **Quarantine is its own row, read by `checkAll`.** New tenant table `agent_quarantines`
   (migration `20261009100000_add_agent_quarantine`, additive): one row per agent, toggled in
   place like `KillSwitch`: `active`, `reason` (deterministic, from the detector), `detector`,
   `evidence` (ids only), `explanationEn` / `explanationAr` (model-written, set at most once),
   `quarantinedByAgentId`, `decisionId`, `quarantinedAt`, `releasedBy` (a `UserProfile` id),
   `releasedAt`, `releaseNote`. `checkAll` checks it right after the AGENT kill switch and returns
   DENY `agent_quarantined`. Because `checkAll` is the one gate, the quarantined agent is refused
   at authorize, at grant redemption and at the agent-runtime gate (LLM proxy, manifest, MCP). A
   lookup failure throws, which every caller already turns into DENY
   `enforcement_dependency_unavailable`. The mTLS guard does not read it, so the agent's identity
   still works and it sees the reason. Not an `AgentStatus` value: the guard rejects any status
   but `ACTIVE`, which would hide the reason, and a status column next to a reason row would be
   two facts that can drift.
2. **A built-in Manar connector.** The `Tool` row named `manar` with `baseEndpoint`
   `manar://builtin` (`isManarBuiltin`); `CredentialBrokerService` runs it
   in-process with no credential (`src/tools/manar-connector.service.ts`), after the full decision
   pipeline, with the same `tool.invocation.*` audit, DLP and `ToolInvocation` row as every other
   tool. Tool name `manar`, two actions, catalog in code (`src/tools/manar-actions.ts`):
   - `manar.activity.read` (read): recent decisions, approvals and tool invocations of the
     tenant's agents, the agent list with a `quarantined` flag, each (agent, tool, action)'s first
     time, and a 24 h decision count per agent as a baseline. Metadata and counts only: no
     parameters (decisions never store them), no inputs hash, and resources as a 16-hex SHA-256
     prefix so distinct targets can be counted without being exposed.
   - `manar.agent.quarantine` (mutating, base risk 0): resource = the target agent id; params
     `reason`, `detector`, `evidence[]`, optional `explanation {en, ar}`. Idempotent and race-safe
     (one row per agent, conditional update, unique index). On an active quarantine the only
     change allowed is attaching the explanation once (`explanationEn IS NULL`). The target is
     looked up in the caller's tenant database, so another tenant's agent is `agent_not_found`.
     An agent may quarantine itself.
   - There is no release, deactivate, approve or delete action. A `ToolAction` row with any other
     name on this tool never runs (`unknown_manar_action`).
   - Not a new `ToolProtocol` value. We tried one first: the demo API on the previous Prisma
     client, sharing the tenant database, failed `GET /tools` with P2023 (unknown enum value)
     as soon as the row existed. A rolling upgrade would hit the same. The row's protocol
     column says `HTTP`; the HTTP adapter can never call it (`manar:` is not an allowed
     outbound scheme), and a tool merely named `manar` elsewhere is an ordinary HTTP tool.
   - `pnpm manar manar-connector:register --tenant <slug>` writes the tool and action rows from
     the catalog (idempotent).
3. **No agent can be granted a loosening capability.** `GrantableToolActionSchema`
   (`src/authorization/grant-triples.ts`) is used for `allowedToolActions` in task creation and
   delegation: on tool `manar` only the two catalog actions are grantable (400 otherwise).
   Forbidding stays unrestricted.
4. **Release is human only.** `POST /agents/:id/quarantine/release` on the human JWT app,
   roles `SECURITY_ADMIN` / `TENANT_OWNER` (same as kill switches), optional `note`. The agent
   mTLS listener has no such route. Loosening fails closed: the `agent.quarantine_released` event
   is written with the throwing `AuditService.record`; if it fails the release is undone and the
   caller gets 503. `GET /quarantines?active=` lists rows for the console.
5. **Records.** Every quarantine runs under an ALLOW `Decision` (ADR-0006) whose id is stored on
   the row. Audit: `agent.quarantined` (actor: the watcher agent; reason, detector, evidence,
   decision id), `agent.quarantine_explained` (the model text, once), `agent.quarantine_released`
   (actor: the human; note). A quarantine is not held back by an audit failure (tightening;
   `recordSafely`), a release is.
6. **The watcher identity** (set up per tenant, demo kit `watcher-setup.mjs`): an agent linked to
   an AI system "Manar Watcher", one task whose grants are exactly the two actions on resource
   `*`, `riskCeiling` 30. `manar.agent.quarantine` scores 25 (baseline 10 + mutating 15), so it
   runs without approval unless a tenant policy asks for one, which is that tenant's choice.

## Alternatives considered

- **Reuse the AGENT kill switch with `source = watcher`.** Needs `activatedBy` to stop being a
  human FK, a second deny reason derived from a source column, and makes the human kill-switch
  deactivate endpoint also release quarantines without the release event. Rejected.
- **`AgentStatus.QUARANTINED`.** Spec §5 says new states join the existing enums, but the mTLS
  guard refuses non-`ACTIVE` agents (no reason reaches the agent), and the evidence and
  explanation still need a home. Rejected for now; the API exposes the quarantine row, and the
  console maps it to the spec's `QUARANTINED` state at its boundary.
- **Spec Phase 7 capture mode** (reads run, mutations recorded, not executed). More useful for an
  investigation and the spec's target; larger (a recording executor, a captured-intents UI).
  Deferred: deny-all is the fail-closed subset.
- **Let the watcher call the human kill-switch API with a service account.** Would give an AI a
  human credential that can also deactivate. Rejected.
- **Do nothing / prompt-only rule.** The rule would hold only as long as the model obeyed.
  Rejected by the brief.

## Consequences

- An AI agent can stop any agent in its tenant within one poll interval, with no human in the
  loop. A buggy or compromised watcher can cause denial of service inside its tenant (never
  outside it, never a loosening). Mitigations: the watcher is rate-limited and idempotent, every
  quarantine is a recorded decision with evidence, a human release is one click, and an AGENT
  kill switch or AI-system suspension stops the watcher itself.
- `manar.activity.read` runs two `groupBy` queries over all decisions per call. Fine at pilot
  volume; needs a summary table or an index on `decisions(createdAt)` at scale.
- The console needs a quarantine badge, the explanation and a Release button (not in this MR).
- Rollback: drop the table (migration note) and the code; delete the `manar` tool row if wanted.

## Enforcement-label impact

None upgraded. Quarantine is `governed` only for actions brokered by Manar (authorize, tools
invoke, MCP, LLM proxy); anything an agent does outside Manar is unaffected and stays
`observed-only` or unknown. The watcher's detection is a heuristic: it adds restriction only and
never feeds an ALLOW.
