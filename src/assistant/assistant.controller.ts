import { UsageMeterService } from '../billing/usage-meter.service';
import {
  Body,
  Controller,
  Headers,
  HttpCode,
  Post,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { z } from 'zod';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import { CatalogService } from '../platform/catalog.service';
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
}
