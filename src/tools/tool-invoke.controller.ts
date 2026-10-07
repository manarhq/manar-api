import {
  Body,
  Controller,
  HttpCode,
  Post,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { CurrentAgent } from '../agent-mtls/agent-context';
import type { AgentContext } from '../agent-mtls/agent-context';
import { AgentMtlsGuard } from '../agent-mtls/agent-mtls.guard';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { ToolInvokeRequestSchema } from './tool-invoke.validation';
import {
  isPendingApproval,
  ToolInvocationService,
} from './tool-invocation.service';

/**
 * `POST /agent/v1/tools/invoke` — the REST door to the tool pipeline
 * (`ToolInvocationService`, shared with the governed MCP server). 200 with
 * the tool result when executed, 202 `{ status: 'PENDING', reason,
 * riskScore, approvalId }` when a human must approve, 403 `{ decision:
 * 'DENY', reason }` otherwise. See docs/tool-gateway.md and docs/approvals.md.
 */
@Controller('agent/v1')
export class ToolInvokeController {
  constructor(private readonly toolInvocation: ToolInvocationService) {}

  @Post('tools/invoke')
  @UseGuards(AgentMtlsGuard)
  @HttpCode(200)
  async invoke(
    @CurrentAgent() agent: AgentContext,
    @Body() body: unknown,
    @Res({ passthrough: true }) reply: FastifyReply,
  ) {
    const input = parseBodyOrThrow(ToolInvokeRequestSchema, body);
    const outcome = await this.toolInvocation.invoke(agent, input, 'REST');
    if (isPendingApproval(outcome)) reply.status(202);
    return outcome;
  }
}
