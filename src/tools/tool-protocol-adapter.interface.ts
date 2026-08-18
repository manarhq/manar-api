import type { ToolActionRecord, ToolRecord } from './tool-registry.service';

/**
 * The result of one attempted tool call, as `CredentialBrokerService`
 * receives it back from whichever `ToolProtocolAdapter` it dispatched to.
 * `data` is the tool's own result payload — by construction, no code path
 * in either adapter ever puts the resolved credential into this object
 * (see `HttpToolAdapter`/`McpToolAdapter`'s own doc comments, and the
 * "credential never leaks" test that greps the actual serialized response
 * for it).
 */
export interface ToolInvocationResult {
  success: boolean;
  /** The tool's own result payload — present only when `success` is `true`. */
  data?: unknown;
  /** A short, credential-free error summary — present only when `success` is `false` (e.g. `"HTTP 503"`, `"request timed out"`, never a raw response body). */
  errorMessage?: string;
}

/**
 * One wire-protocol implementation a `Tool.protocol` value dispatches to.
 * `HttpToolAdapter` (real outbound HTTP) and `McpToolAdapter` (a real MCP
 * client) both implement this identical interface and are driven through
 * the identical `CredentialBrokerService`/`AuthorizationService` pipeline
 * — Section 35's explicit requirement that MCP never gets a separate,
 * weaker path. `credential` is passed as a plain string only to the
 * adapter actually making the call, for exactly as long as it takes to
 * inject it into that one outbound request/connection — never logged,
 * never echoed into the returned `ToolInvocationResult`.
 */
export interface ToolProtocolAdapter {
  invoke(
    tool: ToolRecord,
    action: ToolActionRecord,
    resource: string,
    params: unknown,
    credential: string,
  ): Promise<ToolInvocationResult>;
}
