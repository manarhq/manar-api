import { ENT_AUDIT_EVENT_TYPES } from '../enterprise/common/ent-audit-events';

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
  /** "Approve for 8 hours": a time-boxed allow was created / used (spec 4.6). */
  APPROVAL_GRANT_CREATED: 'approval.grant.created',
  APPROVAL_GRANT_USED: 'approval.grant.used',
  APPROVAL_HANDOVER_COLLECTED: 'approval.handover_collected',
  /** A device approval got no answer in time and was denied ("denied: no answer"). */
  APPROVAL_EXPIRED: 'approval.expired',
  /** A person revoked an approval: cancelled before use, or flagged after use (`usedBeforeRevoke`). */
  APPROVAL_REVOKED: 'approval.revoked',
  /** A person withdrew an 8-hour grant, or lifted a block left by a revoked-after-use approval. */
  APPROVAL_GRANT_REVOKED: 'approval.grant.revoked',
  /** A personal workspace's owner approved their own sensitive request after a fresh sign-in. */
  APPROVAL_SELF_CONFIRMED: 'approval.self_confirmed',
  /** "Pause all AI" was turned on / off for the workspace. */
  WORKSPACE_AI_PAUSED: 'workspace.ai.paused',
  WORKSPACE_AI_RESUMED: 'workspace.ai.resumed',

  /** Phone track: a Telegram chat was linked to / unlinked from a person. No chat id in the event. */
  TELEGRAM_LINK_CREATED: 'telegram.link.created',
  TELEGRAM_LINK_REMOVED: 'telegram.link.removed',

  TOOL_INVOCATION_STARTED: 'tool.invocation.started',
  TOOL_INVOCATION_COMPLETED: 'tool.invocation.completed',
  TOOL_INVOCATION_FAILED: 'tool.invocation.failed',
  /** A mutating call ended without a definite answer; needs reconciliation. */
  TOOL_INVOCATION_OUTCOME_UNKNOWN: 'tool.invocation.outcome_unknown',
  /** ADR-0012: an approved change ran, but the target system shows it did not land where the person approved (e.g. a merge request retargeted mid-merge). */
  APPROVAL_BINDING_VIOLATED: 'tool.invocation.approval_binding_violated',

  POLICY_PUBLISHED: 'policy.published',
  /** Features track: the workspace's start mode (policy preset) was switched; data holds from, to and the new version. */
  START_MODE_CHANGED: 'start_mode.changed',

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

  // docs/edge.md. Egress records come from the edge gateway (hostnames only, never payloads or
  // paths); rule changes are always a person's.
  AGENT_EGRESS_ALLOWED: 'agent.egress.allowed',
  AGENT_EGRESS_DENIED: 'agent.egress.denied',
  AGENT_EGRESS_RULE_ADDED: 'agent.egress_rule.added',
  AGENT_EGRESS_RULE_REMOVED: 'agent.egress_rule.removed',

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
  /** A tenant admin revoked a cloud agent and removed its realm objects. */
  CLOUD_AGENT_DISCONNECTED: 'cloud_agent.disconnected',
  /** A self-registered client is waiting for a tenant admin to confirm it for a ChatGPT agent. */
  CLOUD_AGENT_CLIENT_PENDING: 'cloud_agent.client_pending',
  /** A tenant admin confirmed (or rejected) the waiting client of a ChatGPT agent. */
  CLOUD_AGENT_CLIENT_CONFIRMED: 'cloud_agent.client_confirmed',
  CLOUD_AGENT_CLIENT_REJECTED: 'cloud_agent.client_rejected',
  /** A token with a valid realm signature was refused by the public MCP endpoint (reason and a hash prefix, never the token). */
  CLOUD_MCP_TOKEN_REJECTED: 'cloud_mcp.token_rejected',
  /** A tenant admin configured the realm's Entra ID identity provider. */
  IDENTITY_PROVIDER_CONFIGURED: 'tenant.identity_provider_configured',

  /** Hosts (docs/hosts.md): a machine registered with an install key (new or merged). */
  HOST_REGISTERED: 'host.registered',
  HOST_APPROVED: 'host.approved',
  HOST_REJECTED: 'host.rejected',
  HOST_REVOKED: 'host.revoked',
  /** A known machine registered with a different key or another group's key; waits for an admin. */
  HOST_REKEY_REQUESTED: 'host.rekey_requested',
  /** Host groups, org units and approval rules: before and after, with the actor. */
  HOST_GROUP_CHANGED: 'host_group.changed',
  ORG_UNIT_CHANGED: 'org_unit.changed',
  HOST_APPROVAL_RULE_CHANGED: 'host_approval_rule.changed',
  /** An install key was created (its id, group and limits; never the key). */
  INSTALL_KEY_CREATED: 'install_key.created',
  INSTALL_KEY_REVOKED: 'install_key.revoked',
  /** F2b: customer CA trust, AD connection settings, OU rules and TPM roots changed (before/after, never the AD password). */
  ADCS_TRUSTED_CA_CHANGED: 'adcs_trusted_ca.changed',
  ADCS_SETTINGS_CHANGED: 'adcs_settings.changed',
  AD_OU_RULE_CHANGED: 'ad_ou_rule.changed',
  TPM_TRUST_ROOT_CHANGED: 'tpm_trust_root.changed',
  /** A host moved to another group because its AD OU changed (registration or re-sync). */
  HOST_GROUP_MOVED: 'host.group_moved',
  /** An admin-triggered AD re-sync ran (counts) or could not run (AD unreachable). */
  ADCS_RESYNC_RUN: 'adcs.resync_run',
  /** A host's TPM attestation passed or a challenge was failed. */
  HOST_TPM_VERIFIED: 'host.tpm_verified',
  /** A tenant's plan changed (Stripe, trial start or end). Data: from, to, source. */
  BILLING_PLAN_CHANGED: 'billing.plan.changed',
  /** A card dispute opened or closed: paid features frozen or restored. Data: disputeStatus, entitlementStatus. */
  BILLING_DISPUTE_CHANGED: 'billing.dispute.changed',
  /** The owner removed a device (console "Remove device"): certificates revoked, record kept as REMOVED; it can be installed again. */
  HOST_REMOVED: 'host.removed',
  /** A known machineId registered with a new key: a separate PENDING host, never a key swap. */
  HOST_POSSIBLE_CLONE: 'host.possible_clone',
  /** The device moved itself to another workspace (signed by its own certificate). */
  HOST_MOVED: 'host.moved',
  /** A company device's person left: it stays protected, unassigned. */
  HOST_UNASSIGNED: 'host.unassigned',
  /** A member of a company deleted their Manar account. */
  MEMBER_ACCOUNT_DELETED: 'member.account_deleted',

  // AI tool coverage (launch spec 4.5).
  /** A device reported an AI tool for the first time. */
  TOOL_DISCOVERED: 'tool.discovered',
  /** Protection (hooks, MCP wrap, routing) was installed on a device's tool, or turned off by its owner. */
  TOOL_PROTECTED: 'tool.protected',
  TOOL_UNPROTECTED: 'tool.unprotected',
  /** A non-Claude tool's action was decided through `POST /host/v1/authorize`. */
  HOST_ACTION_DECIDED: 'host.action_decided',

  /** Secrets (spec 4.5): a device reported a secret file opened by an AI tool (masked path, no content). */
  SECRET_TOUCHED: 'secret.touched',
  /** A secret was moved into the device's vault and the device verified it (kind and ref, never the secret). */
  /** A person asked a device to protect a secret in its vault, or to restore it to its file. */
  SECRET_VAULT_REQUESTED: 'secret.vault.requested',
  SECRET_VAULT_RESTORE_REQUESTED: 'secret.vault.restore_requested',
  SECRET_VAULT_STORED: 'secret.vault.stored',
  SECRET_VAULT_RESTORED: 'secret.vault.restored',
  /** A program was let have a vaulted secret (the decision and its scope are in the data). */
  SECRET_VAULT_RELEASED: 'secret.vault.released',
  /** A person withdrew a standing "8 hours" or "Always" vault grant; the device drops it. */
  SECRET_VAULT_GRANT_WITHDRAWN: 'secret.vault.grant_withdrawn',
  SECRET_VAULT_DENIED: 'secret.vault.denied',

  // Tampering a device saw (manar-edge protect; src/hosts/tamper.ts). Data: host, tool, kind, masked path.
  /** A hook refused an AI tool's change to a hook or settings file. */
  PROTECT_TAMPER_SETTINGS_WRITE: 'protect.tamper.settings_write',
  /** Manar's hook was taken out of a settings file it protects; the device put it back. */
  PROTECT_TAMPER_HOOK_REMOVED: 'protect.tamper.hook_removed',
  /** A project's Claude Code settings switch all hooks off (disableAllHooks). */
  PROTECT_TAMPER_HOOKS_DISABLED: 'protect.tamper.hooks_disabled',
  /** Claude Code was started with --settings. */
  PROTECT_TAMPER_SETTINGS_FLAG: 'protect.tamper.settings_flag',
  /** Claude Code ran with CLAUDE_CONFIG_DIR away from ~/.claude. */
  PROTECT_TAMPER_CONFIG_DIR: 'protect.tamper.config_dir',

  /** The device service came back after a crash or kill; data carries how long it was away. */
  HOST_SERVICE_RESTARTED: 'service.restarted',

  // AI spend tracker and secrets-in-prompt guard (DOOR).
  /** DOOR replaced a secret in an outbound prompt with a mask. Data: tool, kind, count, masked sample; never the prompt. */
  DOOR_SECRET_MASKED: 'door.secret.masked',
  /** DOOR refused an outbound prompt that contained a secret (block mode). */
  DOOR_SECRET_BLOCKED: 'door.secret.blocked',
  /** The workspace's AI budget, cap or secrets-guard mode changed (before and after). */
  AI_SPEND_SETTINGS_CHANGED: 'ai_spend.settings_changed',
  /** Month spend crossed the budget (alert) or a tool's cap (the tool is paused on its devices). */
  AI_SPEND_LIMIT_REACHED: 'ai_spend.limit_reached',
  /** A device's usage report was refused (unknown tool, out-of-bound counts). Data: host and reason, never the payload. */
  DOOR_USAGE_REJECTED: 'door.usage.rejected',
  /** DOOR turned requests away because their body could not be checked (unsupported encoding). Data: host and count. */
  DOOR_REQUEST_REFUSED: 'door.request.refused',
  /** One device's spend today is far above the workspace's other devices. Data: host, today's spend, threshold. */
  AI_SPEND_HOST_OUTLIER: 'ai_spend.host_outlier',

  /** Insight: a device reported an MCP server of one of its AI tools for the first time (name, tool, flags; never args or env). */
  MCP_SERVER_DISCOVERED: 'mcp.server.discovered',
  /** Insight: an owner shared a redacted agent session as a public report. */
  SESSION_SHARED: 'session.report.shared',

  /** The workspace changed how far secret blocking goes (off, keys, all). */
  SECRET_SETTINGS_CHANGED: 'secret.settings.changed',

  /** Undo AI file changes: an admin asked a device to put a file back; the device reported the result. */
  HOST_FILE_CHANGE_RESTORE_REQUESTED: 'host.file_change.restore_requested',
  HOST_FILE_CHANGE_RESTORED: 'host.file_change.restored',
  HOST_FILE_CHANGE_RESTORE_FAILED: 'host.file_change.restore_failed',

  /** A launch-offer slot was claimed and Pro was started for 3 months. Data: slot count, months. */
  LAUNCH_OFFER_CLAIMED: 'launch.offer.claimed',
  /** The owner turned the public "Protected by Manar" badge on or off. */
  PROFILE_BADGE_CHANGED: 'profile.badge.changed',
  /** A manager changed the workspace's product improvement data switches. */
  WORKSPACE_DATA_PREFERENCES_CHANGED: 'workspace.data_preferences.changed',
  WORKSPACE_INVITE_CREATED: 'workspace.invite.created',
  WORKSPACE_INVITE_ACCEPTED: 'workspace.invite.accepted',
  WORKSPACE_INVITE_REVOKED: 'workspace.invite.revoked',
  /** Microsoft auto-join was turned on or off by an admin. */
  WORKSPACE_AUTOJOIN_CHANGED: 'workspace.autojoin.changed',
  /** A person joined through the Entra auto-join setting (matched on the verified tid). */
  WORKSPACE_MEMBER_AUTOJOINED: 'workspace.member.autojoined',

  // JAIL (per-site decisions for protected AI tools).
  /** A person allowed or blocked a site for one tool on one device (an answer to a prompt, or by hand). */
  JAIL_SITE_RULE_CREATED: 'jail.site_rule.created',
  /** A person removed a site rule. */
  JAIL_SITE_RULE_REMOVED: 'jail.site_rule.removed',

  // Enterprise and Government invisible mode (src/enterprise/common/ent-audit-events.ts).
  ...ENT_AUDIT_EVENT_TYPES,
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
