import { UsageMeterService } from '../billing/usage-meter.service';
import {
  Body,
  Controller,
  Headers,
  HttpCode,
  Post,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiProduces,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import type { FastifyReply } from 'fastify';
import { z } from 'zod';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import { CatalogService } from '../platform/catalog.service';
import { openSse, type SseStream } from '../common/sse/sse';
import { AssistantChatSchema, AssistantService } from './assistant.service';
import type { AssistantChatResponse } from './assistant.service';

const chatBodySchema = z.toJSONSchema(AssistantChatSchema, {
  io: 'input',
}) as Record<string, unknown>;
delete chatBodySchema.$schema;

/**
 * The console assistant (manar-api ADR-0008). Any signed-in user of the
 * tenant may ask; what the assistant can read is decided per read by the
 * same route guards the console hits, with this user's own token.
 */
@ApiTags('assistant')
@ApiBearerAuth('jwt')
@Controller('assistant')
@UseGuards(JwtAuthGuard)
export class AssistantController {
  constructor(
    private readonly assistant: AssistantService,
    private readonly meter: UsageMeterService,
    private readonly catalog: CatalogService,
  ) {}

  @Post('chat')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Ask the read-only console assistant',
    description:
      'Answers questions about this tenant with sources. Read-only: it has no tool that changes anything, and every read runs as the caller through the normal GET routes and their role checks. `available: false` means no model answered. The conversation is not stored server side; the console sends the history with each question.',
  })
  @ApiBody({ schema: chatBodySchema })
  @ApiResponse({
    status: 200,
    description:
      '`{ available: true, answer, sources[], suggestions[], toolsUsed[] }` or `{ available: false, reason }`.',
  })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 429, type: ErrorResponseDto })
  @ApiResponse({
    status: 402,
    type: ErrorResponseDto,
    description:
      'Paused: the monthly AI allowance is used and no credits or cap are left. Protection is not affected.',
  })
  async chat(
    @CurrentAuth() auth: AuthContext,
    @Headers('authorization') authorization: string | undefined,
    @Body() body: unknown,
  ): Promise<AssistantChatResponse> {
    // JwtAuthGuard already verified this exact header.
    if (!authorization) throw new UnauthorizedException();
    // One AI action (paid extra), given back when no model answered or the request failed.
    return this.meter.ai(
      auth.tenant.id,
      () => this.assistant.chat(auth, authorization, body),
      // "Allow external AI" off: answered politely before anything is metered.
      async () =>
        (await this.catalog.externalAiSwitchedOff(auth.tenant.id, 'assistant'))
          ? ({ available: false, reason: 'ai_switched_off' } as const)
          : null,
    );
  }

  @Post('chat/stream')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Ask the assistant and watch the answer being written (SSE)',
    description:
      'Same request, limits, metering and permissions as `POST /assistant/chat`, answered as a `text/event-stream`. Events: `token` `{t}` (answer text so far, append it), `tool` `{names}` (the model is reading these records: clear the text shown so far), `done` (the final `AssistantChatResponse`; its `answer` replaces the streamed text because it is cleaned and its citations are checked), `error` `{code}`. A `: heartbeat` comment goes out every 10 seconds. Closing the connection stops the model call. Errors before the stream starts (400, 402, 403, 429) are ordinary JSON responses.',
  })
  @ApiBody({ schema: chatBodySchema })
  @ApiProduces('text/event-stream')
  @ApiResponse({ status: 200, description: 'text/event-stream' })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 402, type: ErrorResponseDto })
  @ApiResponse({ status: 429, type: ErrorResponseDto })
  async chatStream(
    @CurrentAuth() auth: AuthContext,
    @Headers('authorization') authorization: string | undefined,
    @Body() body: unknown,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    if (!authorization) throw new UnauthorizedException();
    let sse: SseStream | undefined;
    let streamed = 0;
    try {
      const result = await this.meter.ai(
        auth.tenant.id,
        async () => {
          const answer = await this.assistant.chat(auth, authorization, body, {
            // Open only after the checks that answer with a normal status have passed.
            onReady: () => {
              sse = openSse(reply);
            },
            onToken: (t) => {
              streamed += t.length;
              sse?.send('token', { t });
            },
            onTools: (names) => sse?.send('tool', { names }),
            get signal() {
              return sse?.signal;
            },
          });
          // Stopping after words were written is still an answered question: no refund for it.
          return !answer.available && streamed > 0 && sse?.signal.aborted
            ? ({ stopped: true } as const)
            : answer;
        },
        // "Allow external AI" off: the same polite answer as the plain endpoint, nothing metered.
        async () =>
          (await this.catalog.externalAiSwitchedOff(
            auth.tenant.id,
            'assistant',
          ))
            ? ({ available: false, reason: 'ai_switched_off' } as const)
            : null,
      );
      if ('stopped' in result) return;
      (sse ??= openSse(reply)).send('done', result);
    } catch (error) {
      if (!sse) throw error; // still a normal HTTP error (400, 402, 403, 429, ...)
      const status =
        typeof (error as { getStatus?: () => number }).getStatus === 'function'
          ? (error as { getStatus: () => number }).getStatus()
          : 500;
      sse.send('error', { code: status === 500 ? 'internal' : status });
    } finally {
      sse?.end();
    }
  }
}
