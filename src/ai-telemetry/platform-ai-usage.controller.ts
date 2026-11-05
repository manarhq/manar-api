import {
  BadRequestException,
  Controller,
  Get,
  Query,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { z } from 'zod';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { PlatformAuthGuard } from '../platform/platform-auth.guard';
import { PlatformOwnerGuard } from '../platform/platform-owner.guard';
import { AI_PRICE_TABLE } from './ai-prices';
import { AI_FEATURES, AiTelemetryService } from './ai-telemetry.service';

const DAY = 86_400_000;
const date = z.iso.date().transform((d) => new Date(`${d}T00:00:00Z`));

export const UsageQuerySchema = z
  .object({
    /** UTC dates, inclusive. Default: the last 30 days. */
    from: date.optional(),
    to: date.optional(),
    /** Comma list of `workspace`, `feature`, `model`, `day`. Default `feature,model`. */
    groupBy: z
      .string()
      .default('feature,model')
      .transform((s) => s.split(',').filter(Boolean))
      .pipe(z.array(z.enum(['workspace', 'feature', 'model', 'day'])).max(4)),
    workspaceId: z.uuid().optional(),
    feature: z.enum(AI_FEATURES).optional(),
    model: z.string().max(100).optional(),
  })
  .strict();

const TopQuerySchema = z
  .object({ limit: z.coerce.number().int().min(1).max(100).default(10) })
  .strict();

/**
 * Staff-only AI cost and quality numbers for the Desk AI page (performance program, decisions 7
 * to 9). Platform token plus the staff Owner role (`PLATFORM_OWNER_ROLE`): money is for Owners.
 * Counts, tokens, cost and latency only. There is no prompt or answer anywhere in this data.
 */
@ApiTags('platform')
@ApiBearerAuth('platform')
@UseGuards(PlatformAuthGuard, PlatformOwnerGuard)
@Controller('platform/v1/ai-usage')
export class PlatformAiUsageController {
  constructor(private readonly telemetry: AiTelemetryService) {}

  @Get()
  @ApiOperation({
    summary:
      'Tokens, cost, p50/p95 latency and error rate, grouped by workspace, feature, model and/or day',
  })
  async usage(@Query() query: unknown) {
    const q = parseBodyOrThrow(UsageQuerySchema, query);
    const to = q.to ?? new Date();
    const from = q.from ?? new Date(to.getTime() - 29 * DAY);
    if (to.getTime() - from.getTime() > 92 * DAY || from > to)
      throw new BadRequestException(
        'from must be before to, at most 93 days apart',
      );
    return {
      priceVersion: AI_PRICE_TABLE.version,
      from: from.toISOString().slice(0, 10),
      to: to.toISOString().slice(0, 10),
      groupBy: q.groupBy,
      rows: await this.telemetry.summary({
        from,
        to,
        groupBy: q.groupBy,
        tenantId: q.workspaceId,
        feature: q.feature,
        model: q.model,
      }),
    };
  }

  @Get('top-workspaces')
  @ApiOperation({ summary: 'The workspaces that cost the most today (UTC)' })
  async top(@Query() query: unknown) {
    const { limit } = parseBodyOrThrow(TopQuerySchema, query);
    return {
      priceVersion: AI_PRICE_TABLE.version,
      day: new Date().toISOString().slice(0, 10),
      rows: await this.telemetry.topWorkspaces(new Date(), limit),
    };
  }

  @Get('spikes')
  @ApiOperation({
    summary:
      'Spend-spike signal: workspaces (and the platform, tenantId null) whose spend today is at least 3x their 7-day median and at least 5 USD',
  })
  async spikes() {
    return { spikes: await this.telemetry.spikes() };
  }

  @Get('prices')
  @ApiOperation({ summary: 'The price table cost is computed from' })
  prices() {
    return AI_PRICE_TABLE;
  }
}
