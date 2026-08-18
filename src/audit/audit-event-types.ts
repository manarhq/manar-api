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

  TOOL_INVOCATION_STARTED: 'tool.invocation.started',
  TOOL_INVOCATION_COMPLETED: 'tool.invocation.completed',
  TOOL_INVOCATION_FAILED: 'tool.invocation.failed',

  POLICY_PUBLISHED: 'policy.published',

  // Phase 10b (AI Advisory Pipeline Integration) — see docs/ai-security-model.md.
  /** A severe DLP finding on outbound tool-call params blocked the call before any tool contact. */
  DLP_BLOCKED: 'dlp.blocked',
  /** A DLP finding in a tool's returned result was redacted before being returned to the agent. */
  DLP_RESULT_REDACTED: 'dlp.result_redacted',
  /** `AiAdvisoryClient.analyzePromptInjection` detected a prompt-injection attempt in a tool's returned result. */
  PROMPT_INJECTION_DETECTED: 'prompt_injection.detected',
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
