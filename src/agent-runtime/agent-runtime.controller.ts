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
import { setTimeout as sleep } from 'node:timers/promises';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
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
import { failClosed } from '../common/fail-closed/fail-closed';
import { AgentTaskAccessService } from './agent-task-access.service';
import {
  parseToolName,
  toolName,
  ToolManifestService,
} from './tool-manifest.service';

/** ADR-0007: the read-only tool an MCP client waits on an approval with. */
export const APPROVAL_STATUS_TOOL = 'manar_approval_status';
// The MCP TS SDK client times a request out at 60 s by default: stay under it.
const APPROVAL_WAIT_MAX_SECONDS = 50;
const APPROVAL_WAIT_DEFAULT_SECONDS = 25;
const APPROVAL_POLL_MS = 2_000;
export const MAX_CONCURRENT_APPROVAL_WAITS_PER_AGENT = 4;
// ponytail: in-process counter, right for one API replica. With several
// replicas, move it to a Redis counter per tenant+agent with a TTL.
const approvalWaitsInFlight = new Map<string, number>();

export const ApprovalStatusArgsSchema = z.object({
  approvalId: z.string().min(1).max(64),
  waitSeconds: z
    .number()
    .int()
    .min(0)
    .max(APPROVAL_WAIT_MAX_SECONDS)
    .default(APPROVAL_WAIT_DEFAULT_SECONDS),
});

interface ApprovalRow {
  id: string;
  status: string;
  toolId: string;
  actionId: string;
  resource: string;
  expiresAt: Date;
  grant: {
    consumedAt: Date | null;
    revokedAt: Date | null;
    expiresAt: Date;
  } | null;
}

/** What the agent should do next for each approval state (ADR-0007). */
export function describeApproval(row: ApprovalRow): Record<string, unknown> {
  const tool = toolName(row.toolId, row.actionId);
  const base = {
    approvalId: row.id,
    status: row.status,
    tool,
    resource: row.resource,
  };
  const grant = row.grant;
  switch (row.status) {
    case 'PENDING':
      return {
        ...base,
        expiresAt: row.expiresAt,
        nextStep: `Still waiting for a person to decide in the Manar console. Nothing has run. Call ${APPROVAL_STATUS_TOOL} again to keep waiting.`,
      };
    case 'APPROVED':
      if (
        grant &&
        !grant.consumedAt &&
        !grant.revokedAt &&
        grant.expiresAt.getTime() > Date.now()
      ) {
        return {
          ...base,
          grantExpiresAt: grant.expiresAt,
          nextStep: `Approved. Call ${tool} again now with exactly the same resource and params. Manar re-checks the decision and runs it once.`,
        };
      }
      return {
        ...base,
        nextStep:
          'This approval was already used or has lapsed. Running the action again needs a new approval.',
      };
    case 'DENIED':
      return {
        ...base,
        nextStep:
          'Refused, by a person or by Manar re-checking it at approval time. Do not retry; tell the user.',
      };
    case 'REVOKED':
      return {
        ...base,
        nextStep:
          'A person withdrew this approval. Do not run the action; tell the user.',
      };
    default:
      return {
        ...base,
        nextStep:
          'No one decided in time. Ask the user before requesting it again.',
      };
  }
}

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

export function methodNotAllowed(reply: FastifyReply): void {
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
 * `POST /agent/v1/tools/invoke`: one decision path, two doors. An approved
 * action completes by calling the same tool again (ADR-0007), waiting with
 * `manar_approval_status` in between.
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
    const { tenantClient, task, hiddenTools } =
      await this.access.assertTaskAccess(agent, taskId);
    return this.manifest.build(tenantClient, task, hiddenTools);
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
    await this.serveMcp(agent, taskId, body, request, reply);
  }

  /** Also the public cloud-agent MCP endpoint's handler (src/cloud-mcp/), after its OAuth guard. */
  async serveMcp(
    agent: AgentContext,
    taskId: string,
    body: unknown,
    request: FastifyRequest,
    reply: FastifyReply,
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
        const { tenantClient, task, hiddenTools } =
          await this.access.assertTaskAccess(agent, taskId);
        manifest = await this.manifest.build(tenantClient, task, hiddenTools);
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
        tools: [
          ...manifest.tools.map((tool) => ({
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
          {
            name: APPROVAL_STATUS_TOOL,
            description: `Status of an approval Manar asked a person for: PENDING, APPROVED, DENIED or EXPIRED, with what to do next. While PENDING it waits up to waitSeconds (default ${APPROVAL_WAIT_DEFAULT_SECONDS}, max ${APPROVAL_WAIT_MAX_SECONDS}) for the decision; call it again if it is still PENDING. Read-only: it never runs the action.`,
            inputSchema: {
              type: 'object' as const,
              properties: {
                approvalId: {
                  type: 'string',
                  description: 'The approvalId a PENDING result returned.',
                },
                waitSeconds: {
                  type: 'integer',
                  minimum: 0,
                  maximum: APPROVAL_WAIT_MAX_SECONDS,
                },
              },
              required: ['approvalId'],
            },
            annotations: { readOnlyHint: true, destructiveHint: false },
          },
        ],
      };
    });

    server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
      if (request.params.name === APPROVAL_STATUS_TOOL) {
        return this.approvalStatus(
          agent,
          taskId,
          request.params.arguments ?? {},
          extra.signal,
        );
      }
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
        const outcome = await this.toolInvocation.invoke(
          agent,
          parsed.data,
          'MCP',
        );
        if (isPendingApproval(outcome)) {
          return okResult({
            status: 'PENDING',
            approvalId: outcome.approvalId,
            reason: outcome.reason,
            riskScore: outcome.riskScore,
            nextStep: `A person must approve this in the Manar console. Nothing has run. Tell the user you are waiting, call ${APPROVAL_STATUS_TOOL} with this approvalId to wait for the decision, and once it is APPROVED call ${request.params.name} again with exactly the same arguments; Manar then runs it once.`,
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

  /**
   * `manar_approval_status` (ADR-0007): same task gate as `tools/list`, then
   * only an approval of this agent in this session's task; anything else is
   * `approval_not_found`, never "exists elsewhere". Reads only; no grant
   * token is ever returned. Waits while PENDING, up to `waitSeconds`; stops
   * when the client goes away (`signal`); an agent already holding
   * `MAX_CONCURRENT_APPROVAL_WAITS_PER_AGENT` waits gets the current status
   * at once.
   */
  async approvalStatus(
    agent: AgentContext,
    taskId: string,
    args: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<CallToolResult> {
    const parsed = ApprovalStatusArgsSchema.safeParse(args);
    if (!parsed.success) return deniedResult('invalid_arguments');
    const { approvalId } = parsed.data;

    const waiter = `${agent.tenant.id}:${agent.agent.id}`;
    const inFlight = approvalWaitsInFlight.get(waiter) ?? 0;
    const waits =
      parsed.data.waitSeconds > 0 &&
      inFlight < MAX_CONCURRENT_APPROVAL_WAITS_PER_AGENT;
    if (waits) approvalWaitsInFlight.set(waiter, inFlight + 1);
    try {
      const { tenantClient } = await this.access.assertTaskAccess(
        agent,
        taskId,
      );
      const deadline =
        Date.now() + (waits ? parsed.data.waitSeconds * 1_000 : 0);
      // ponytail: polls PostgreSQL every 2 s per waiting call; a LISTEN/NOTIFY
      // push if many agents wait at once.
      for (;;) {
        const row = await failClosed('tenant-db', () =>
          tenantClient.approvalRequest.findUnique({
            where: { id: approvalId },
            include: { grant: true },
          }),
        );
        if (!row || row.agentId !== agent.agent.id || row.taskId !== taskId) {
          return deniedResult('approval_not_found');
        }
        const remaining = deadline - Date.now();
        if (row.status !== 'PENDING' || remaining <= 0 || signal?.aborted) {
          return okResult(describeApproval(row));
        }
        try {
          await sleep(Math.min(APPROVAL_POLL_MS, remaining), undefined, {
            signal,
          });
        } catch {
          // Aborted: the client is gone; nobody reads this answer.
          return okResult(describeApproval(row));
        }
      }
    } catch (error) {
      if (error instanceof HttpException) {
        return deniedResult(reasonOf(error));
      }
      throw error;
    } finally {
      if (waits) {
        const left = (approvalWaitsInFlight.get(waiter) ?? 1) - 1;
        if (left > 0) approvalWaitsInFlight.set(waiter, left);
        else approvalWaitsInFlight.delete(waiter);
      }
    }
  }
}
