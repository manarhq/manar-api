import { randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  Post,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { FastifyInstance, FastifyReply } from 'fastify';
import { CurrentAgent } from '../agent-mtls/agent-context';
import type { AgentContext } from '../agent-mtls/agent-context';
import { AgentMtlsGuard } from '../agent-mtls/agent-mtls.guard';
import { getCorrelationId } from '../logging/correlation-id.store';
import { anthropicError } from './llm-anthropic';
import { LlmAnthropicService } from './llm-anthropic.service';
import { LlmProxyService } from './llm-proxy.service';

export const ANTHROPIC_MESSAGES_PATH = '/agent/v1/llm/anthropic/v1/messages';
/** The local gateway's own cap (manar-edge design section 5); a coding agent's context is large. */
export const ANTHROPIC_BODY_LIMIT = 10 * 1024 * 1024;

/**
 * Fastify's 1 MiB default stays on every other agent route; only the Anthropic messages route
 * takes up to 10 MiB. Call on the agent mTLS app's Fastify instance before `init`/`listen`.
 */
export function allowLargeLlmBodies(fastify: FastifyInstance): void {
  fastify.addHook('onRoute', (route) => {
    if (route.url === ANTHROPIC_MESSAGES_PATH)
      route.bodyLimit = ANTHROPIC_BODY_LIMIT;
  });
}

const one = (v: string | string[] | undefined): string | undefined =>
  Array.isArray(v) ? v.join(',') : v || undefined;

/** OpenAI-compatible chat completions and Anthropic messages for an agent's task (ADR-0002). */
@Controller('agent/v1/llm')
export class LlmProxyController {
  constructor(
    private readonly proxy: LlmProxyService,
    private readonly anthropic: LlmAnthropicService,
  ) {}

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

  /**
   * Anthropic Messages (`/v1/messages` behind the local gateway). Errors use the Anthropic error
   * shape with Manar's `decision`/`reason` alongside; a 4xx carries `x-should-retry: false` so
   * Claude Code stops instead of retrying a refusal.
   */
  @Post('anthropic/v1/messages')
  @UseGuards(AgentMtlsGuard)
  async anthropicMessages(
    @CurrentAgent() agent: AgentContext,
    @Headers() headers: Record<string, string | string[] | undefined>,
    @Body() body: unknown,
    @Res() reply: FastifyReply,
  ) {
    const taskId = one(headers['x-manar-task-id']);
    void reply.header('x-manar-request-id', getCorrelationId() ?? randomUUID());
    if (taskId) void reply.header('x-manar-task-id', taskId);
    const closed = new AbortController();
    reply.raw.on('close', () => closed.abort());
    try {
      if (!taskId) {
        throw new BadRequestException('X-Manar-Task-Id header is required');
      }
      const result = await this.anthropic.messages(
        agent,
        taskId,
        body,
        {
          version: one(headers['anthropic-version']),
          beta: one(headers['anthropic-beta']),
        },
        closed.signal,
      );
      if ('json' in result) return reply.status(200).send(result.json);
      return reply
        .status(200)
        .header('content-type', 'text/event-stream; charset=utf-8')
        .header('cache-control', 'no-cache')
        .header('x-accel-buffering', 'no')
        .send(Readable.from(result.stream));
    } catch (error) {
      const { status, body: errorBody } = anthropicError(error);
      if (status < 500) void reply.header('x-should-retry', 'false');
      return reply.status(status).send(errorBody);
    }
  }

  /** What this install serves, in a shape the OpenAI SDK and Claude Code's discovery both read. */
  @Get('models')
  @UseGuards(AgentMtlsGuard)
  models(@CurrentAgent() agent: AgentContext) {
    return this.anthropic.models(agent);
  }
}
