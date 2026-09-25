import { randomUUID } from 'node:crypto';
import {
  BadRequestException,
  Body,
  Controller,
  Headers,
  HttpCode,
  Post,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { CurrentAgent } from '../agent-mtls/agent-context';
import type { AgentContext } from '../agent-mtls/agent-context';
import { AgentMtlsGuard } from '../agent-mtls/agent-mtls.guard';
import { getCorrelationId } from '../logging/correlation-id.store';
import { LlmProxyService } from './llm-proxy.service';

/** OpenAI-compatible chat completions for an agent's task (ADR-0002). */
@Controller('agent/v1/llm')
export class LlmProxyController {
  constructor(private readonly proxy: LlmProxyService) {}

  @Post('chat/completions')
  @UseGuards(AgentMtlsGuard)
  @HttpCode(200)
  async chatCompletions(
    @CurrentAgent() agent: AgentContext,
    @Headers('x-manar-task-id') taskId: string | undefined,
    @Body() body: unknown,
    @Res({ passthrough: true }) reply: FastifyReply,
  ) {
    if (!taskId) {
      throw new BadRequestException('X-Manar-Task-Id header is required');
    }
    void reply.header('x-manar-task-id', taskId);
    void reply.header('x-manar-request-id', getCorrelationId() ?? randomUUID());
    return this.proxy.complete(agent, taskId, body);
  }
}
