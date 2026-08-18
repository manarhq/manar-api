import { createServer, Server as HttpServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';

export interface RecordedMcpCall {
  toolName: string;
  arguments: unknown;
  /** The `Authorization` header the underlying HTTP request carried — proves `McpToolAdapter` actually injected the resolved credential at the transport layer, never as a tool argument. */
  authorizationHeader: string | undefined;
}

/**
 * A minimal, real MCP server (the official `@modelcontextprotocol/sdk`,
 * `McpServer` + `StreamableHTTPServerTransport` — not a hand-rolled
 * JSON-RPC stand-in) exposing exactly one tool, `lookup`. Built for this
 * phase's own tests, to prove `McpToolAdapter`'s architecture is real
 * end-to-end — not one of Phase 7a's demo SOC tools (out of scope — see
 * the design spec).
 *
 * A fresh `McpServer` + stateless `StreamableHTTPServerTransport`
 * (`sessionIdGenerator: undefined`) is built *per HTTP request* rather
 * than one long-lived transport instance reused across a client's
 * initialize -> notify -> call sequence: reusing a single stateless
 * transport instance across that sequence was found, empirically, to
 * 500 on the client's `notifications/initialized` follow-up (a real
 * interaction observed against `@modelcontextprotocol/sdk@1.30.0`'s
 * bundled `@hono/node-server` Node-compat wrapper, not a guess) — the
 * per-request pattern is both a documented-elsewhere way to run a
 * genuinely stateless MCP HTTP server and reliably avoids that.
 * `McpToolAdapter` itself already connects fresh per invocation (see its
 * own doc comment), so this matches the client's actual usage pattern.
 */
export class McpTestServer {
  private httpServer: HttpServer | undefined;

  readonly calls: RecordedMcpCall[] = [];

  private buildMcpServer(): McpServer {
    const mcpServer = new McpServer({
      name: 'manar-mcp-test-server',
      version: '1.0.0',
    });

    mcpServer.registerTool(
      'lookup',
      {
        description:
          'Test-only MCP tool -- records the call and echoes back the resource it was asked to look up.',
        inputSchema: {
          resource: z.string(),
          query: z.string().optional(),
        },
      },
      (args: { resource: string; query?: string }, extra) => {
        const authorizationHeader = extra.requestInfo?.headers?.[
          'authorization'
        ] as string | undefined;
        this.calls.push({
          toolName: 'lookup',
          arguments: args,
          authorizationHeader,
        });
        const payload = { found: true, resource: args.resource };
        return {
          content: [{ type: 'text' as const, text: JSON.stringify(payload) }],
          structuredContent: payload,
        };
      },
    );

    return mcpServer;
  }

  async start(): Promise<string> {
    this.httpServer = createServer((req, res) => {
      const mcpServer = this.buildMcpServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
      });
      res.on('close', () => {
        void transport.close();
        void mcpServer.close();
      });
      mcpServer
        .connect(transport)
        .then(() => transport.handleRequest(req, res))
        .catch((error: unknown) => {
          if (!res.headersSent) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
          }
          res.end(
            JSON.stringify({
              error: error instanceof Error ? error.message : String(error),
            }),
          );
        });
    });

    await new Promise<void>((resolve) =>
      this.httpServer?.listen(0, '127.0.0.1', resolve),
    );
    const address = this.httpServer.address() as AddressInfo;
    return `http://127.0.0.1:${address.port}/mcp`;
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      this.httpServer?.close((error) => (error ? reject(error) : resolve()));
    });
  }

  reset(): void {
    this.calls.length = 0;
  }
}
