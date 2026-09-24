import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { AppConfig } from '../config/env.validation';
import {
  assertSafeOutboundUrl,
  UnsafeOutboundUrlError,
} from '../common/ssrf/url-safety';
import { parseSsrfAllowedHosts } from '../common/ssrf/ssrf.config';
import { validateAgainstSchema } from './json-schema-validator.util';
import type {
  ToolInvocationResult,
  ToolProtocolAdapter,
} from './tool-protocol-adapter.interface';
import type { ToolActionRecord, ToolRecord } from './tool-registry.service';

const MCP_REQUEST_TIMEOUT_MS = 10_000;

/**
 * Release 2026-11-11 — argument names this adapter owns, which a caller's
 * `params` may therefore never supply.
 *
 * `resource` is Manar's own request-scoping concept and is the exact
 * string `AuthorizationService.authorize` evaluated, that
 * `ApprovalRequest`/`AuthorizationGrant` is bound to, and that the
 * `ToolInvocation` row and audit event record. It is passed to the MCP
 * tool as a normal argument so the target can see what it is being asked
 * to act on.
 *
 * The defect this guards against: the arguments object was built as
 * `{ resource, ...params }`, spreading caller-controlled `params` **after**
 * the canonical field. A caller invoking with `resource: "host-42"` and
 * `params: { resource: "host-999" }` therefore had `host-42` authorized,
 * hashed into the grant, written to the `ToolInvocation` row and recorded
 * in the audit chain — while the MCP server received and acted on
 * `host-999`. That is an authorization bypass whose audit trail states
 * the wrong target, so nothing downstream (approvals, evidence export,
 * compliance mapping) can detect it after the fact.
 *
 * The fix is to **reject** a colliding key rather than to silently reorder
 * the spread. Reordering would make the canonical value win, but it would
 * also quietly discard what the caller actually asked for, leaving a
 * request that did something other than what it said with no error — the
 * same class of dishonesty in a different place. A collision is a caller
 * bug or an attack; either way it deserves a refusal.
 *
 * Note that `validateAgainstSchema` above cannot be relied on for this:
 * stored `inputSchema` values are not required to set
 * `additionalProperties: false`, and the seeded demo action's schema is
 * the wide-open `{ type: 'object' }`.
 */
const RESERVED_MCP_ARGUMENT_NAMES = new Set(['resource']);

/** Shutdown handshake budget — deliberately shorter than the request budget; a slow close must never dominate a request's latency. */
const MCP_CLOSE_TIMEOUT_MS = 2_000;

/**
 * A **real** Model Context Protocol client (`@modelcontextprotocol/sdk`,
 * the official TypeScript SDK — not a hand-rolled approximation of its
 * JSON-RPC wire format), connecting over the Streamable HTTP transport to
 * `tool.baseEndpoint` as an MCP server URL and invoking `action.name` as
 * an MCP tool call. Proven against a minimal test MCP server built for
 * this phase's own tests (`test/support/mcp-test-server.ts`) — not one of
 * Phase 7a's demo SOC tools, just enough surface to prove this adapter
 * architecture is real (see docs/mcp.md).
 *
 * Every MCP call goes through the *exact same*
 * `CredentialBrokerService`/`AuthorizationService` pipeline as an HTTP
 * tool call — this adapter is invoked from the identical call site in
 * `CredentialBrokerService`, with no branch anywhere that skips
 * authorization, input validation, or invocation recording for MCP
 * specifically (Section 35's explicit requirement — see
 * docs/tool-gateway.md).
 *
 * The resolved credential is injected as an `Authorization: Bearer`
 * header on the underlying HTTP requests the Streamable HTTP transport
 * makes (`requestInit.headers` — MCP's base transport has no first-class
 * "auth" concept of its own; this is the same bearer-token convention
 * `HttpToolAdapter` uses, applied at the transport layer instead of a
 * per-call parameter) — never placed into the JSON-RPC tool-call
 * arguments, so it can never appear in an MCP tool's own request logging.
 *
 * Connects fresh for every single invocation (a new `Client` + transport,
 * closed again once the call completes or fails) rather than pooling a
 * persistent MCP session across calls — simpler and correct for this
 * phase's call volume; a real high-throughput deployment integrating a
 * specific MCP server might want connection reuse, which is a documented,
 * deliberate simplification here, not an oversight.
 */
@Injectable()
export class McpToolAdapter implements ToolProtocolAdapter {
  private readonly logger = new Logger(McpToolAdapter.name);
  private readonly ssrfAllowedHosts: Set<string>;

  constructor(configService: ConfigService<AppConfig, true>) {
    this.ssrfAllowedHosts = parseSsrfAllowedHosts(
      configService.get('SSRF_ALLOWED_HOSTS', { infer: true }),
    );
  }

  async invoke(
    tool: ToolRecord,
    action: ToolActionRecord,
    resource: string,
    params: unknown,
    credential: string,
  ): Promise<ToolInvocationResult> {
    const validation = validateAgainstSchema(action.inputSchema, params);
    if (!validation.valid) {
      return {
        success: false,
        errorMessage: `Invalid params for action "${action.name}": ${validation.errors}`,
      };
    }

    // See RESERVED_MCP_ARGUMENT_NAMES: a caller-supplied `resource` would
    // otherwise reach the MCP server in place of the authorized one.
    const collidingArgument = this.findReservedArgumentCollision(params);
    if (collidingArgument !== undefined) {
      this.logger.warn(
        `Rejected MCP tool call to "${tool.name}/${action.name}": params supplied the reserved argument "${collidingArgument}", which would override the authorized value`,
      );
      return {
        success: false,
        errorMessage: `Invalid params for action "${action.name}": "${collidingArgument}" is a reserved argument name and cannot be supplied by the caller`,
      };
    }

    // Phase 12a (SSRF protection) -- see HttpToolAdapter's identical
    // call-time check for why this is re-validated on every invocation
    // rather than trusted from registration time.
    try {
      await assertSafeOutboundUrl(tool.baseEndpoint, {
        allowedHosts: this.ssrfAllowedHosts,
      });
    } catch (error) {
      if (error instanceof UnsafeOutboundUrlError) {
        this.logger.warn(
          `Blocked MCP tool call to "${tool.name}/${action.name}": ${error.reasonCode}`,
        );
        return {
          success: false,
          errorMessage: 'blocked_by_outbound_url_policy',
        };
      }
      throw error;
    }

    const client = new Client({ name: 'manar-tool-gateway', version: '1.0.0' });
    const transport = new StreamableHTTPClientTransport(
      new URL(tool.baseEndpoint),
      {
        requestInit: {
          headers: { Authorization: `Bearer ${credential}` },
        },
      },
    );

    let callSent = false;
    try {
      // The SDK's own default for `initialize` is 60s, so without an
      // explicit timeout here this adapter's declared 10s budget applied to
      // nothing on the connect path: a slow or hostile MCP server could
      // hold a request for ~60s before the tool call was even attempted.
      // The whole connect -> invoke -> close lifecycle is bounded, not just
      // the final call.
      await client.connect(transport, { timeout: MCP_REQUEST_TIMEOUT_MS });

      callSent = true;
      const result = await client.callTool(
        {
          name: action.name,
          // resource is Manar's own request-scoping concept, not an MCP
          // primitive -- passed through as a normal tool argument
          // alongside params so the target MCP tool can see what it's
          // being asked to act on.
          // Canonical fields are spread LAST as defence in depth. The
          // collision check above is the actual control; this ordering
          // means that even if some future edit removes or bypasses that
          // check, the authorized `resource` still wins over anything the
          // caller supplied.
          arguments: { ...(params as Record<string, unknown>), resource },
        },
        undefined,
        { timeout: MCP_REQUEST_TIMEOUT_MS },
      );

      if (result.isError) {
        return {
          success: false,
          errorMessage:
            this.summarizeTextContent(result.content) ??
            'MCP tool call returned an error',
        };
      }

      return {
        success: true,
        data: result.structuredContent ?? result.content,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(
        `MCP tool call to "${tool.name}/${action.name}" failed: ${message}`,
      );
      // Gate 0 finding R1: once `tools/call` was sent, a lost answer on a
      // mutating or destructive action means the side effect may have
      // happened. Connect failures happen before anything was asked.
      if (callSent && (action.mutating || action.destructive)) {
        return {
          success: false,
          errorMessage: `MCP call failed: ${message}`,
          outcomeUnknown: true,
        };
      }
      return { success: false, errorMessage: `MCP call failed: ${message}` };
    } finally {
      // Bounded like every other step: a server that never completes its
      // shutdown handshake must not hold this request open.
      await Promise.race([
        client.close().catch(() => undefined),
        new Promise((resolve) => setTimeout(resolve, MCP_CLOSE_TIMEOUT_MS)),
      ]);
    }
  }

  /**
   * Returns the first caller-supplied key that collides with an argument
   * name this adapter owns, or `undefined` when there is none.
   *
   * Only own enumerable string keys are considered, which is what a spread
   * would actually copy — checking anything else would reject requests
   * that the spread would not in fact have been affected by.
   */
  private findReservedArgumentCollision(params: unknown): string | undefined {
    if (
      typeof params !== 'object' ||
      params === null ||
      Array.isArray(params)
    ) {
      return undefined;
    }
    for (const key of Object.keys(params)) {
      if (RESERVED_MCP_ARGUMENT_NAMES.has(key)) {
        return key;
      }
    }
    return undefined;
  }

  private summarizeTextContent(content: unknown): string | undefined {
    if (!Array.isArray(content)) return undefined;
    const texts = content
      .filter(
        (item): item is { type: 'text'; text: string } =>
          typeof item === 'object' &&
          item !== null &&
          (item as { type?: unknown }).type === 'text',
      )
      .map((item) => item.text);
    return texts.length > 0 ? texts.join(' ') : undefined;
  }
}
