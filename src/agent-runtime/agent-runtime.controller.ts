import {
  Body,
  Controller,
  Delete,
  Get,
  HttpException,
  Param,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { CurrentAgent } from '../agent-mtls/agent-context';
import type { AgentContext } from '../agent-mtls/agent-context';
import { AgentMtlsGuard } from '../agent-mtls/agent-mtls.guard';
import { ToolInvokeRequestSchema } from '../tools/tool-invoke.validation';
import {
  isPendingApproval,
  ToolInvocationService,
} from '../tools/tool-invocation.service';
import { AgentTaskAccessService } from './agent-task-access.service';
import { parseToolName, ToolManifestService } from './tool-manifest.service';

/** Reason code carried by an HttpException from the pipeline or the access gate. */
export function reasonOf(error: HttpException): string {
  const body = error.getResponse();
  if (body && typeof body === 'object' && 'reason' in body) {
    return String(body.reason);
  }
  const status = error.getStatus();
  if (status === 404) return 'tool_not_found';
  if (status === 409) return 'tool_disabled';
  if (status === 400) return 'invalid_arguments';
  return 'denied';
}

function deniedResult(reason: string): CallToolResult {
  const structuredContent = { status: 'DENIED', reason };
  return {
    isError: true,
    structuredContent,
    content: [{ type: 'text', text: JSON.stringify(structuredContent) }],
  };
}

function okResult(structuredContent: Record<string, unknown>): CallToolResult {
  return {
    isError: false,
    structuredContent,
    content: [{ type: 'text', text: JSON.stringify(structuredContent) }],
  };
}

function methodNotAllowed(reply: FastifyReply): void {
  void reply
    .status(405)
    .header('Allow', 'POST')
    .send({
      jsonrpc: '2.0',
      error: { code: -32000, message: 'Method not allowed.' },
      id: null,
    });
}

/**
 * The per-task tool manifest and the governed MCP server (ADR-0002,
 * Addendum 01 §C.3). Both are derived from the task's effective grant set;
 * `tools/call` runs `ToolInvocationService`, the exact pipeline behind
 * `POST /agent/v1/tools/invoke`: one decision path, two doors.
 */
@Controller('agent/v1/tasks/:taskId')
@UseGuards(AgentMtlsGuard)
export class AgentRuntimeController {
  constructor(
    private readonly access: AgentTaskAccessService,
    private readonly manifest: ToolManifestService,
    private readonly toolInvocation: ToolInvocationService,
  ) {}

  @Get('tool-manifest')
  async toolManifest(
    @CurrentAgent() agent: AgentContext,
    @Param('taskId') taskId: string,
  ) {
    const { tenantClient, task } = await this.access.assertTaskAccess(
      agent,
      taskId,
    );
    return this.manifest.build(tenantClient, task);
  }

  /**
   * MCP Streamable HTTP, stateless: a fresh `Server` + transport per request
   * (the pattern `test/support/mcp-test-server.ts` documents for SDK
   * 1.30.0), JSON responses rather than SSE.
   */
  @Post('mcp')
  async mcp(
    @CurrentAgent() agent: AgentContext,
    @Param('taskId') taskId: string,
    @Body() body: unknown,
    @Req() request: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const server = this.buildMcpServer(agent, taskId);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    reply.hijack();
    reply.raw.on('close', () => {
      void transport.close();
      void server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(request.raw, reply.raw, body);
  }

  /** Stateless server: no standalone SSE stream (GET) and no sessions to delete (DELETE). */
  @Get('mcp')
  mcpGet(@Res() reply: FastifyReply): void {
    methodNotAllowed(reply);
  }

  @Delete('mcp')
  mcpDelete(@Res() reply: FastifyReply): void {
    methodNotAllowed(reply);
  }

  private buildMcpServer(agent: AgentContext, taskId: string): Server {
    const server = new Server(
      { name: 'manar-governed-mcp', version: '1.0.0' },
      { capabilities: { tools: {} } },
    );

    server.setRequestHandler(ListToolsRequestSchema, async () => {
      let manifest;
      try {
        const { tenantClient, task } = await this.access.assertTaskAccess(
          agent,
          taskId,
        );
        manifest = await this.manifest.build(tenantClient, task);
      } catch (error) {
        if (error instanceof HttpException) {
          const reason = reasonOf(error);
          throw new McpError(ErrorCode.InvalidRequest, `DENY: ${reason}`, {
            status: 'DENIED',
            reason,
          });
        }
        throw error;
      }
      return {
        tools: manifest.tools.map((tool) => ({
          name: tool.name,
          description: tool.description,
          inputSchema: {
            type: 'object' as const,
            properties: {
              resource: {
                type: 'string',
                description: `Target resource id. Allowed: ${tool.resourceSelector.join(', ')}`,
              },
              params: tool.inputSchema as object,
            },
            required: ['resource'],
          },
          annotations: {
            readOnlyHint: !tool.mutating,
            destructiveHint: tool.destructive,
          },
        })),
      };
    });

    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const target = parseToolName(request.params.name);
      if (!target) return deniedResult('unknown_tool');
      const args = request.params.arguments ?? {};
      const parsed = ToolInvokeRequestSchema.safeParse({
        taskId,
        toolId: target.toolId,
        actionId: target.actionId,
        resource: args.resource,
        params: args.params ?? {},
      });
      if (!parsed.success) return deniedResult('invalid_arguments');

      try {
        const outcome = await this.toolInvocation.invoke(agent, parsed.data);
        if (isPendingApproval(outcome)) {
          return okResult({
            status: 'PENDING',
            approvalId: outcome.approvalId,
            reason: outcome.reason,
            riskScore: outcome.riskScore,
          });
        }
        return okResult({
          ...outcome,
          status: 'EXECUTED',
          outcome: outcome.success
            ? 'SUCCESS'
            : outcome.outcomeUnknown
              ? 'UNKNOWN'
              : 'FAILURE',
        });
      } catch (error) {
        if (error instanceof HttpException) {
          return deniedResult(reasonOf(error));
        }
        throw error;
      }
    });

    return server;
  }
}
