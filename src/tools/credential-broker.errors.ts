/** Thrown by `CredentialBrokerService.invoke` when `toolId` doesn't resolve to a registered `Tool`. The caller (`ToolInvokeController`) maps this to a 404. */
export class ToolNotFoundError extends Error {
  constructor(toolId: string) {
    super(`Tool "${toolId}" is not registered`);
    this.name = 'ToolNotFoundError';
  }
}

/** Thrown when `actionId` doesn't resolve to a registered `ToolAction` on that tool. */
export class ToolActionNotFoundError extends Error {
  constructor(toolId: string, actionId: string) {
    super(`Tool "${toolId}" has no registered action "${actionId}"`);
    this.name = 'ToolActionNotFoundError';
  }
}

/** Thrown when `Tool.enabled` is `false` — Section 35's explicit "disabled tool -> invocation fails cleanly even if authorization would otherwise allow it" requirement. */
export class ToolDisabledError extends Error {
  constructor(toolId: string) {
    super(`Tool "${toolId}" is disabled`);
    this.name = 'ToolDisabledError';
  }
}

/**
 * Phase 10b: thrown by `CredentialBrokerService.invoke` when
 * `AiAdvisoryClient.analyzeDlp` reports a severe finding on outbound
 * `params` — the call is blocked before any tool contact is ever attempted
 * (see docs/ai-security-model.md's DLP-before-call checkpoint). The
 * message is deliberately generic (never echoes the sensitive value, or
 * even the finding type, back to the caller) — mirrors
 * `AuthorizationService`'s own "not_authorized" generic-DENY-reason
 * posture for the same "don't let a caller probe the shape of a security
 * control via its own error messages" reason.
 */
export class DlpBlockedError extends Error {
  constructor() {
    super('dlp_policy_violation');
    this.name = 'DlpBlockedError';
  }
}
