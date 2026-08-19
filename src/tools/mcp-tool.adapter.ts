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

    try {
      await client.connect(transport);

      const result = await client.callTool(
        {
          name: action.name,
          // resource is Manar's own request-scoping concept, not an MCP
          // primitive -- passed through as a normal tool argument
          // alongside params so the target MCP tool can see what it's
          // being asked to act on.
          arguments: { resource, ...(params as Record<string, unknown>) },
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
      return { success: false, errorMessage: `MCP call failed: ${message}` };
    } finally {
      await client.close().catch(() => undefined);
    }
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
