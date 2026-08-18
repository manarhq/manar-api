# OCSF mapping

Phase 9b (Section 50). `src/audit/ocsf/` transforms a Manar `AuditEvent`
into its [Open Cybersecurity Schema Framework](https://ocsf.io/) (OCSF)
representation for the event types that genuinely fit an OCSF class, and
returns a clearly-labeled unmapped result for every other type — never a
forced/fake mapping. See `src/audit/ocsf/ocsf-mapper.ts` and
`src/audit/ocsf/ocsf-mapper.spec.ts`.

## Targeted schema version

**OCSF v1.9.0** (`https://schema.ocsf.io/1.9.0/`) — the current stable
release as of this phase; v1.10.0 exists only as a `-dev` prerelease.
Pinned explicitly in `src/audit/ocsf/ocsf-types.ts`'s `OCSF_SCHEMA_VERSION`
constant so a future schema bump is a deliberate, reviewed change to that
file, not silent drift.

## Why these three classes, and no others

OCSF's catalog is heavily weighted toward host/network/directory-service
telemetry (Windows/Linux security logs, EDR, firewalls, cloud IAM). Manar's
own audit events are mostly about a different domain entirely — a
governed, delegable, time-bounded grant of authority to a non-human agent,
and a human-approval workflow gating some of those actions — which OCSF
v1.9.0 has no dedicated class for. Rather than stretch an ill-fitting class
over that domain, this phase maps only the three event families that
_do_ correspond to something OCSF already models well:

| Manar `eventType`(s)                                                              | OCSF class                 | Why it fits                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| --------------------------------------------------------------------------------- | -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `agent.enrolled`, `agent.enrollment_failed`                                       | Authentication `[3002]`    | Agent enrollment is literally "a principal obtains a working credential/session" — OCSF's `Logon`/`Logoff` activities and `Success`/`Failure` status map directly, with the agent as `user`.                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `agent.revoked`                                                                   | Authentication `[3002]`    | Modeled as `Logoff` — the agent's certificate no longer authenticates, ending its ability to establish new authenticated sessions, the closest OCSF activity to "this principal's session/credential is now invalid."                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `authorization.allowed`, `authorization.denied`, `authorization.pending_approval` | Authorize Session `[3003]` | This class models "privileges assigned to a session" — Manar's authorization decision assigns (or denies/defers) exactly that: the specific `toolId:actionId` privilege for the task's session, to the deciding agent. `status_id` carries ALLOW/DENY/PENDING as Success/Failure/Unknown. **Imperfect fit, documented**: OCSF's `Authorize Session` was designed for host/directory privilege-elevation audit logs (e.g. Windows event 4672), not API-level policy decisions — reused here because no closer class exists in v1.9.0, and the shape (privileges assigned to a session, by an actor, with a status) still genuinely describes what happened. |
| `tool.invocation.started`, `tool.invocation.completed`, `tool.invocation.failed`  | API Activity `[6003]`      | A tool invocation _is_ an API call (Section 33-35: every tool action goes through `HttpToolAdapter`/`McpToolAdapter`) — `api.operation`/`api.service.name` map to `actionId`/`toolId` directly, `status_id` to started/completed/failed.                                                                                                                                                                                                                                                                                                                                                                                                                   |

`activity_id` for API Activity is deliberately always `0` (`Unknown`),
never guessed as Create/Read/Update/Delete: `AuditEvent.data` for a tool
invocation never carries the invoked `ToolAction`'s `mutating`/
`destructive` flags (Section 46's credential-secrecy-adjacent minimalism —
see `docs/audit-chain.md`'s "tool invocation" retrofit note), so there is
no reliable signal to pick a specific CRUD activity from without guessing.
Guessing wrong would misrepresent a read-only SIEM search as a `Delete`,
which is worse than leaving it `Unknown`.

### Deliberately left unmapped

| Manar `eventType`(s)                                                                  | Why no OCSF v1.9.0 class fits                                                                                                                                                                                                                                                                |
| ------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `task.created`, `task.revoked`, `task.delegated`                                      | No OCSF class models a time/execution-bounded, sub-delegable authority grant to a non-human principal. Forcing this into `Authorize Session` (privileges on an authenticated _session_, not a standalone delegable grant object with its own lifecycle) would misrepresent the actual model. |
| `approval.requested`, `approval.approved`, `approval.denied`, `approval.grant_issued` | OCSF v1.9.0 has no human-approval-workflow class — nothing models a pending request awaiting a second human's decision, distinct from the authorization decision itself.                                                                                                                     |
| `policy.published`                                                                    | No policy-authoring/versioned-governance-document lifecycle class exists — the closest candidates (Application Activity classes) model runtime API calls, not document publication.                                                                                                          |
| `audit.retention_executed` (Phase 9b)                                                 | Infrastructure self-audit of Manar's own audit chain — not a security event about an external actor at all; no real-world OCSF analog.                                                                                                                                                       |

`mapAuditEventToOcsf` returns `{ mapped: false, eventType, reason }` for
every one of these (and any future/unknown `eventType`) — the `reason`
string names exactly why, mirroring the table above
(`src/audit/ocsf/ocsf-mapper.ts`'s `unmappedReason`).

## Manar-specific fields with no OCSF equivalent

Every mapped event's Manar-specific decision inputs (risk score, matched
policy version, denial reason, task risk ceiling, raw OpenFGA booleans,
error messages, ...) are carried in OCSF's own documented `unmapped`
object attribute — the schema's built-in escape hatch for exactly this
situation — never by repurposing an unrelated official field (e.g. never
stuffing a risk score into `severity_id`, which has its own fixed,
unrelated OCSF meaning).

## Scope: this is a transform, not a delivery mechanism

`mapAuditEventToOcsf` is a pure function (`AuditEvent` in, `OcsfMappingResult`
out) — nothing in this phase stores or indexes OCSF-shaped documents.
`OpenSearchIndexService` indexes the Manar-native `AuditEvent` shape (see
the "OpenSearch indexing" section of `docs/audit-chain.md`); this mapper
is the reusable foundation a future webhooks/external-SIEM-export phase
would call to shape its outbound payloads, not that delivery mechanism
itself — explicitly out of scope this phase.
