/**
 * Section 29's event-type catalog, restricted to the names this phase's
 * retrofit points actually produce (the full catalog has more entries for
 * later phases' own retrofit work — not reproduced here, YAGNI). Every
 * `AuditService.record(...)` call site in this codebase uses one of these
 * constants rather than a hand-typed string literal, so a typo can never
 * silently create a new, unintended event type.
 */
export const AUDIT_EVENT_TYPES = {
  AGENT_ENROLLED: 'agent.enrolled',
  AGENT_ENROLLMENT_FAILED: 'agent.enrollment_failed',
  AGENT_REVOKED: 'agent.revoked',

  TASK_CREATED: 'task.created',
  TASK_REVOKED: 'task.revoked',
  TASK_DELEGATED: 'task.delegated',

  AUTHORIZATION_ALLOWED: 'authorization.allowed',
  AUTHORIZATION_DENIED: 'authorization.denied',
  AUTHORIZATION_PENDING_APPROVAL: 'authorization.pending_approval',

  APPROVAL_REQUESTED: 'approval.requested',
  APPROVAL_APPROVED: 'approval.approved',
  APPROVAL_DENIED: 'approval.denied',
  APPROVAL_GRANT_ISSUED: 'approval.grant_issued',
  APPROVAL_GRANT_REDEEMED: 'approval.grant_redeemed',
  APPROVAL_GRANT_REJECTED: 'approval.grant_rejected',
  /** ADR-0007: a repeated MCP call was answered with the still-open approval for the same call. */
  APPROVAL_REUSED: 'approval.reused',
  /** ADR-0007: an open approval was expired because a fresh decision scored higher or changed policy version or reason. */
  APPROVAL_SUPERSEDED: 'approval.superseded',
  /** ADR-0011: the approver collected the value an approved action produced for them (field names only). */
  APPROVAL_HANDOVER_COLLECTED: 'approval.handover_collected',

  TOOL_INVOCATION_STARTED: 'tool.invocation.started',
  TOOL_INVOCATION_COMPLETED: 'tool.invocation.completed',
  TOOL_INVOCATION_FAILED: 'tool.invocation.failed',
  /** A mutating call ended without a definite answer; needs reconciliation. */
  TOOL_INVOCATION_OUTCOME_UNKNOWN: 'tool.invocation.outcome_unknown',
  /** ADR-0012: an approved change ran, but the target system shows it did not land where the person approved (e.g. a merge request retargeted mid-merge). */
  APPROVAL_BINDING_VIOLATED: 'tool.invocation.approval_binding_violated',

  POLICY_PUBLISHED: 'policy.published',

  /** Phase 9b (Retention, Section 48) — written by `AuditRetentionWorkflow`'s Activity; see `src/audit/retention/`. */
  AUDIT_RETENTION_EXECUTED: 'audit.retention_executed',

  // Phase 10b (AI Advisory Pipeline Integration) — see docs/ai-security-model.md.
  /** A severe DLP finding on outbound tool-call params blocked the call before any tool contact. */
  DLP_BLOCKED: 'dlp.blocked',
  /** A DLP finding in a tool's returned result was redacted before being returned to the agent. */
  DLP_RESULT_REDACTED: 'dlp.result_redacted',
  /** `AiAdvisoryClient.analyzePromptInjection` detected a prompt-injection attempt in a tool's returned result. */
  PROMPT_INJECTION_DETECTED: 'prompt_injection.detected',

  /** One call through the LLM proxy (ADR-0002): metadata only, never prompt or completion content. */
  LLM_REQUEST: 'llm.request',
  /** One question to the console assistant (manar-api ADR-0008): metadata only, never question, answer or tool output. */
  ASSISTANT_REQUEST: 'assistant.request',

  // Kill-switch phase (Section 32) — see docs/kill-switches.md.
  /** A kill switch (any of the five scopes) was activated — see `src/kill-switches/`. */
  KILL_SWITCH_ACTIVATED: 'kill_switch.activated',
  /** A kill switch was deactivated. */
  KILL_SWITCH_DEACTIVATED: 'kill_switch.deactivated',

  // ADR-0009 (watcher). Actor of `agent.quarantined` is the agent that
  // quarantined; actor of `agent.quarantine_released` is always a human.
  AGENT_QUARANTINED: 'agent.quarantined',
  /** The watcher attached its model-written explanation to an active quarantine (once). */
  AGENT_QUARANTINE_EXPLAINED: 'agent.quarantine_explained',
  AGENT_QUARANTINE_RELEASED: 'agent.quarantine_released',

  // Phase 14 (Users/Roles/Settings) — see src/users/, src/tenant-settings/.
  /** `POST /users/:id/role-bindings` granted a role — see `UsersService.grantRole`. */
  USER_ROLE_GRANTED: 'user.role_granted',
  /** `DELETE /users/:id/role-bindings/:role` revoked a role — see `UsersService.revokeRole`. */
  USER_ROLE_REVOKED: 'user.role_revoked',
  /** `PATCH /tenant/settings` updated one or more residency/AI-governance flags — see `TenantSettingsService.updateSettings`. */
  TENANT_SETTINGS_UPDATED: 'tenant.settings_updated',
  /** Manar staff changed this tenant's feature flags, packs or LLM route through manar-fleet (src/platform/catalog.*). */
  CATALOG_UPDATED: 'catalog.updated',

  // Phase 15a (Incidents, Section 70) — see src/incidents/.
  /** `POST /incidents` created a new incident — see `IncidentsService.createIncident`. */
  INCIDENT_CREATED: 'incident.created',
  /** `PATCH /incidents/:id` changed `status` — see `IncidentsService.updateIncident`. Not recorded for a PATCH that changes only title/description/severity/relatedCorrelationIds without a status change. */
  INCIDENT_STATUS_CHANGED: 'incident.status_changed',

  // Release 2026-11-11 (brief §3.1) — the AI-system inventory. Every
  // mutation of a governance record is audited, including the link/unlink
  // assertions: "who said this agent belongs to this system, and when" is
  // exactly the provenance an assessment later has to cite.
  AI_SYSTEM_CREATED: 'ai_system.created',
  AI_SYSTEM_UPDATED: 'ai_system.updated',
  AI_SYSTEM_STATE_CHANGED: 'ai_system.state_changed',
  AI_SYSTEM_AGENT_LINKED: 'ai_system.agent_linked',
  AI_SYSTEM_AGENT_UNLINKED: 'ai_system.agent_unlinked',
  AI_SYSTEM_TOOL_LINKED: 'ai_system.tool_linked',
  AI_SYSTEM_TOOL_UNLINKED: 'ai_system.tool_unlinked',

  // Cloud agents (docs/cloud-agents.md).
  /** A tenant admin connected a cloud agent (Copilot Studio or ChatGPT) or changed its binding. */
  CLOUD_AGENT_CONNECTED: 'cloud_agent.connected',
  CLOUD_AGENT_UPDATED: 'cloud_agent.updated',
  /** A token presented to the public MCP endpoint was refused (reason and a hash prefix, never the token). */
  CLOUD_MCP_TOKEN_REJECTED: 'cloud_mcp.token_rejected',
  /** A tenant admin configured the realm's Entra ID identity provider. */
  IDENTITY_PROVIDER_CONFIGURED: 'tenant.identity_provider_configured',
} as const;

export type AuditEventType =
  (typeof AUDIT_EVENT_TYPES)[keyof typeof AUDIT_EVENT_TYPES];

/**
 * `{ type, id }` — never a bare string, so a consumer of `AuditEvent.actor`
 * never has to guess which kind of principal caused an event. `type:
 * 'system'` is for events with no single accountable human/agent (e.g. a
 * genuinely automated re-evaluation outcome that isn't attributable to the
 * human who originally clicked approve — see `src/approvals/grant.service.ts`
 * retrofit call sites).
 */
export interface AuditActor {
  type: 'human' | 'agent' | 'system';
  id: string;
}
