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
