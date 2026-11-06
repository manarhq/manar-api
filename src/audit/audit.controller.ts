import {
  AI_SWITCHED_OFF_REASON,
  aiSwitchedOff,
  AiAdvisoryClient,
} from '../ai-advisory/ai-advisory-client.service';
import { UsageMeterService } from '../billing/usage-meter.service';
import {
  BadRequestException,
  Body,
  ConflictException,
  Controller,
  Get,
  NotFoundException,
  Param,
  ParseUUIDPipe,
  HttpCode,
  Post,
  Query,
  Res,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiProduces,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import type { FastifyReply } from 'fastify';
import { runAiStream } from '../ai-advisory/ai-stream';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import { parseLimit } from '../common/pagination/cursor-pagination';
import { EntitlementsService } from '../billing/entitlements.service';
import { AuditSearchService } from './audit-search.service';
import { AuditService } from './audit.service';
import {
  AuditCheckpointIndexError,
  AuditEventNotCheckpointedError,
  AuditEventNotFoundError,
  AuditProofService,
} from './checkpoint/audit-proof.service';
import {
  CheckpointSigner,
  NoCheckpointKeyError,
} from './checkpoint/checkpoint-signer';
import {
  AuditEventProofDto,
  AuditSearchResponseDto,
  CheckpointPublicKeyDto,
  InvestigateAuditRequestDto,
  InvestigateAuditResponseDto,
  VerifyAuditChainResponseDto,
} from './audit.dto';
import { InvestigateAuditSchema } from './audit.validation';

/** Parses a query-param date/time bound (`from`/`to`); throws 400 for anything unparseable — same "never leak a stack trace" convention `parseBodyOrThrow` uses. */
function parseDateParam(
  raw: string | undefined,
  paramName: string,
): Date | undefined {
  if (raw === undefined) return undefined;
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) {
    throw new BadRequestException(
      `Invalid "${paramName}" — must be an ISO-8601 date-time`,
    );
  }
  return parsed;
}

/** Parses a query-param integer bound (`riskMin`/`riskMax`); throws 400 for anything unparseable/out of range. */
function parseRiskParam(
  raw: string | undefined,
  paramName: string,
): number | undefined {
  if (raw === undefined) return undefined;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 100) {
    throw new BadRequestException(
      `Invalid "${paramName}" — must be an integer 0-100`,
    );
  }
  return parsed;
}

/**
 * `GET /audit/verify` (Section 47) — human-facing only (never exposed on
 * the mTLS agent surface: an agent has no business auditing the chain it's
 * itself a subject of). Gated to the three roles the design spec names:
 * `AUDITOR`/`SECURITY_ADMIN`/`TENANT_OWNER` — this is `AUDITOR`'s first
 * real consumer anywhere in this codebase (the role has existed since
 * Phase 3 but no endpoint had gated on it until now).
 */
@ApiTags('audit')
@ApiBearerAuth('jwt')
@Controller('audit')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('AUDITOR', 'SECURITY_ADMIN', 'TENANT_OWNER')
export class AuditController {
  constructor(
    private readonly auditService: AuditService,
    private readonly auditSearchService: AuditSearchService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
    private readonly auditProofService: AuditProofService,
    private readonly checkpointSigner: CheckpointSigner,
    private readonly entitlements: EntitlementsService,
    private readonly meter: UsageMeterService,
    private readonly aiAdvisory: AiAdvisoryClient,
  ) {}

  /** Events older than the plan's window are hidden (never deleted): the lower bound moves up to it. */
  private async clampFrom(
    tenantId: string,
    from?: Date,
  ): Promise<Date | undefined> {
    const floor = await this.entitlements.auditSearchFloor(tenantId);
    if (!floor) return from;
    return from && from > floor ? from : floor;
  }

  @Get()
  @ApiOperation({
    summary: 'Search/browse audit events',
    description:
      'Queries the OpenSearch-indexed, search-optimized copy of the tamper-evident audit chain (Section 45) — never Postgres directly. Cursor-paginated, newest first. Requires AUDITOR, SECURITY_ADMIN, or TENANT_OWNER.',
  })
  @ApiQuery({
    name: 'eventType',
    required: false,
    description: 'Comma-separated list of exact eventType values (OR).',
  })
  @ApiQuery({ name: 'correlationId', required: false })
  @ApiQuery({ name: 'agentId', required: false })
  @ApiQuery({ name: 'taskId', required: false })
  @ApiQuery({ name: 'toolId', required: false })
  @ApiQuery({ name: 'actionId', required: false })
  @ApiQuery({
    name: 'decision',
    required: false,
    description:
      'ALLOW, DENY, APPROVAL_REQUIRED, APPROVE, or DENY (approval decisions).',
  })
  @ApiQuery({ name: 'riskMin', required: false, type: Number })
  @ApiQuery({ name: 'riskMax', required: false, type: Number })
  @ApiQuery({
    name: 'from',
    required: false,
    description: 'ISO-8601 — inclusive lower bound on timestamp.',
  })
  @ApiQuery({
    name: 'to',
    required: false,
    description: 'ISO-8601 — inclusive upper bound on timestamp.',
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Max 100, default 20.',
  })
  @ApiQuery({
    name: 'cursor',
    required: false,
    description: 'Opaque `nextCursor` from a previous page.',
  })
  @ApiResponse({ status: 200, type: AuditSearchResponseDto })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async search(
    @CurrentAuth() auth: AuthContext,
    @Query('eventType') eventType?: string,
    @Query('correlationId') correlationId?: string,
    @Query('agentId') agentId?: string,
    @Query('taskId') taskId?: string,
    @Query('toolId') toolId?: string,
    @Query('actionId') actionId?: string,
    @Query('decision') decision?: string,
    @Query('riskMin') riskMin?: string,
    @Query('riskMax') riskMax?: string,
    @Query('from') from?: string,
    @Query('to') to?: string,
    @Query('limit') limit?: string,
    @Query('cursor') cursor?: string,
  ): Promise<AuditSearchResponseDto> {
    return this.auditSearchService.search({
      tenantId: auth.tenant.id,
      filters: {
        eventType: eventType
          ? eventType
              .split(',')
              .map((s) => s.trim())
              .filter(Boolean)
          : undefined,
        correlationId,
        agentId,
        taskId,
        toolId,
        actionId,
        decision,
        riskMin: parseRiskParam(riskMin, 'riskMin'),
        riskMax: parseRiskParam(riskMax, 'riskMax'),
        from: await this.clampFrom(
          auth.tenant.id,
          parseDateParam(from, 'from'),
        ),
        to: parseDateParam(to, 'to'),
      },
      limit: parseLimit(limit),
      cursor,
    });
  }

  @Post('investigate')
  @ApiOperation({
    summary: 'AI-advisory audit investigation (Phase 10c)',
    description:
      "Performs its own tenant-scoped OpenSearch query (the exact same AuditSearchService.search GET /audit uses -- never a client-suppliable tenant), then passes only those already-authorized results to manar-ai's InvestigateAudit RPC as context. manar-ai never performs its own retrieval. Requires AUDITOR, SECURITY_ADMIN, or TENANT_OWNER. `available: false` means manar-ai was unreachable -- never a crash, never a fabricated answer.",
  })
  @ApiBody({ type: InvestigateAuditRequestDto })
  @ApiResponse({ status: 201, type: InvestigateAuditResponseDto })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async investigate(
    @CurrentAuth() auth: AuthContext,
    @Body() body: unknown,
  ): Promise<InvestigateAuditResponseDto> {
    const input = parseBodyOrThrow(InvestigateAuditSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    // One AI action (paid extra), given back when no model answered.
    return this.meter.ai(
      auth.tenant.id,
      async () =>
        this.auditSearchService.investigateAudit(
          await this.investigateInput(auth, tenantClient, input),
        ),
      () => this.switchedOffAnswer(auth.tenant.id),
    );
  }

  @Post('investigate/stream')
  @HttpCode(200)
  @ApiOperation({
    summary: 'AI-advisory audit investigation, streamed (SSE)',
    description:
      'Same request, retrieval, roles, metering and result as `POST /audit/investigate`, as a `text/event-stream`: `delta` `{t}` events carry the answer text as the model writes it (already redacted; append them), then `done` with the response body of the plain endpoint (its `result.answer` replaces the streamed text), or `error` `{code}`. A `: heartbeat` comment goes out every 10 seconds. Closing the connection stops the model call. 400, 402 and 403 are ordinary JSON responses sent before the stream starts.',
  })
  @ApiBody({ type: InvestigateAuditRequestDto })
  @ApiProduces('text/event-stream')
  @ApiResponse({ status: 200, description: 'text/event-stream' })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async investigateStream(
    @CurrentAuth() auth: AuthContext,
    @Body() body: unknown,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const input = parseBodyOrThrow(InvestigateAuditSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    const request = await this.investigateInput(auth, tenantClient, input);
    await runAiStream(
      reply,
      this.meter,
      auth.tenant.id,
      (hooks) => this.auditSearchService.investigateAudit(request, hooks),
      () => this.switchedOffAnswer(auth.tenant.id),
    );
  }

  private async switchedOffAnswer(tenantId: string) {
    return aiSwitchedOff(await this.aiAdvisory.aiGate(tenantId))
      ? {
          available: false as const,
          reason: AI_SWITCHED_OFF_REASON,
          result: null,
          contextEventCount: 0,
        }
      : null;
  }

  /** The tenant-scoped retrieval request both investigate endpoints run. */
  private async investigateInput(
    auth: AuthContext,
    tenantClient: Awaited<ReturnType<TenantDatabaseManager['getClient']>>,
    input: ReturnType<typeof InvestigateAuditSchema.parse>,
  ) {
    return {
      tenantId: auth.tenant.id,
      tenantClient,
      question: input.question,
      filters: {
        eventType: input.eventType
          ? input.eventType
              .split(',')
              .map((s) => s.trim())
              .filter(Boolean)
          : undefined,
        correlationId: input.correlationId,
        agentId: input.agentId,
        taskId: input.taskId,
        toolId: input.toolId,
        actionId: input.actionId,
        decision: input.decision,
        riskMin: input.riskMin,
        riskMax: input.riskMax,
        from: await this.clampFrom(
          auth.tenant.id,
          parseDateParam(input.from, 'from'),
        ),
        to: parseDateParam(input.to, 'to'),
      },
      contextLimit: input.contextLimit ?? 10,
    };
  }

  @Get('verify')
  @ApiOperation({
    summary: 'Verify the tamper-evident audit chain',
    description:
      "Walks every AuditEvent in recorded order, recomputing each row's hash and confirming chain linkage (anchor-aware: tolerates retention-pruned history). Requires AUDITOR, SECURITY_ADMIN, or TENANT_OWNER.",
  })
  @ApiResponse({ status: 200, type: VerifyAuditChainResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async verify(@CurrentAuth() auth: AuthContext) {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return this.auditService.verifyAuditChain(tenantClient, auth.tenant.id);
  }

  @Get('events/:id/proof')
  @ApiOperation({
    summary: 'Inclusion proof for one audit event',
    description:
      "The event's Merkle path to a root in a signed checkpoint (SEAL), plus that checkpoint, so a recipient can verify the event without trusting Manar. 409 while the event is not yet covered by a checkpoint (they are written every second). Requires AUDITOR, SECURITY_ADMIN, or TENANT_OWNER.",
  })
  @ApiResponse({ status: 200, type: AuditEventProofDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  @ApiResponse({ status: 409, type: ErrorResponseDto })
  async proof(
    @CurrentAuth() auth: AuthContext,
    @Param('id', new ParseUUIDPipe()) id: string,
  ) {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    try {
      return await this.auditProofService.proveEvent(tenantClient, id);
    } catch (error) {
      if (error instanceof AuditEventNotFoundError) {
        throw new NotFoundException({
          code: error.code,
          message: error.message,
        });
      }
      if (error instanceof AuditEventNotCheckpointedError) {
        throw new ConflictException({
          code: error.code,
          message: error.message,
          retryAfterMs: error.retryAfterMs,
        });
      }
      if (error instanceof AuditCheckpointIndexError) {
        // An integrity failure in this tenant's audit store, not a retry case.
        throw new ConflictException({
          code: error.code,
          message: error.message,
        });
      }
      throw error;
    }
  }

  @Get('checkpoints/public-key')
  @ApiOperation({
    summary: "This tenant's checkpoint signing key",
    description:
      "The Ed25519 public key that signs this tenant's audit checkpoints (SEALs). Requires AUDITOR, SECURITY_ADMIN, or TENANT_OWNER.",
  })
  @ApiResponse({ status: 200, type: CheckpointPublicKeyDto })
  @ApiResponse({
    status: 404,
    type: ErrorResponseDto,
    description: 'No checkpoint written yet for this tenant.',
  })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async publicKey(@CurrentAuth() auth: AuthContext) {
    try {
      return await this.checkpointSigner.publicKey(auth.tenant.id);
    } catch (error) {
      if (error instanceof NoCheckpointKeyError) {
        throw new NotFoundException({
          code: error.code,
          message: error.message,
        });
      }
      throw error;
    }
  }
}
