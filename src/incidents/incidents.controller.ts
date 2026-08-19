import {
  Body,
  Controller,
  Get,
  NotFoundException,
  Param,
  Patch,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import {
  parseCursor,
  parseLimit,
} from '../common/pagination/cursor-pagination';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { IncidentNotFoundError } from './incidents.errors';
import { IncidentsService } from './incidents.service';
import {
  CreateIncidentSchema,
  SummarizeIncidentSchema,
  UpdateIncidentSchema,
} from './incidents.validation';
import {
  CreateIncidentRequestDto,
  IncidentListResponseDto,
  IncidentSummaryDto,
  SummarizeIncidentRequestDto,
  SummarizeIncidentResponseDto,
  UpdateIncidentRequestDto,
} from './incidents.dto';

/** Translates `IncidentsService`'s typed domain errors into HTTP responses — mirrors `UsersController`'s identical `mapUserErrors` convention. */
async function mapIncidentErrors<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof IncidentNotFoundError) {
      throw new NotFoundException(error.message);
    }
    throw error;
  }
}

/**
 * Phase 15a (Section 70) — `/incidents`. Plain CRUD linked to existing
 * audit data via `relatedCorrelationIds`. Phase 10c adds `POST
 * /incidents/summarize`, an AI-advisory read-only operation (see
 * `IncidentsService.summarizeIncident`'s own doc comment). Any
 * authenticated tenant user may create/view/update/summarize an incident
 * this phase — mirrors `UsersController`'s posture (no `RequireRole`
 * gate): incident response is a cross-functional activity (SOC operators,
 * security admins, approvers) this phase doesn't attempt to finely
 * role-gate, and every create/status-change is audited regardless of who
 * performed it.
 */
@ApiTags('incidents')
@ApiBearerAuth('jwt')
@Controller('incidents')
@UseGuards(JwtAuthGuard)
export class IncidentsController {
  constructor(
    private readonly incidentsService: IncidentsService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

  @Post()
  @ApiOperation({
    summary: 'Create an incident',
    description: 'Audited (incident.created).',
  })
  @ApiBody({ type: CreateIncidentRequestDto })
  @ApiResponse({ status: 201, type: IncidentSummaryDto })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  async create(
    @CurrentAuth() auth: AuthContext,
    @Body() body: unknown,
  ): Promise<IncidentSummaryDto> {
    const input = parseBodyOrThrow(CreateIncidentSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return this.incidentsService.createIncident(tenantClient, {
      ...input,
      tenantId: auth.tenant.id,
      createdByUserId: auth.user.id,
    });
  }

  @Get()
  @ApiOperation({
    summary: 'List incidents',
    description:
      'Cursor-paginated, newest first. Optional status/severity filters.',
  })
  @ApiQuery({
    name: 'status',
    required: false,
    enum: ['OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED'],
  })
  @ApiQuery({
    name: 'severity',
    required: false,
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
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
  @ApiResponse({ status: 200, type: IncidentListResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  async list(
    @CurrentAuth() auth: AuthContext,
    @Query('status') status?: string,
    @Query('severity') severity?: string,
    @Query('limit') limit?: string,
    @Query('cursor') cursor?: string,
  ): Promise<IncidentListResponseDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return this.incidentsService.listIncidents(tenantClient, {
      status: status as
        'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'CLOSED' | undefined,
      severity: severity as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | undefined,
      limit: parseLimit(limit),
      cursor: parseCursor(cursor),
    });
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get one incident' })
  @ApiParam({ name: 'id', description: 'Incident ID', format: 'uuid' })
  @ApiResponse({ status: 200, type: IncidentSummaryDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({
    status: 404,
    type: ErrorResponseDto,
    description: 'Incident not found.',
  })
  async get(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
  ): Promise<IncidentSummaryDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return mapIncidentErrors(() =>
      this.incidentsService.getIncidentOrThrow(tenantClient, id),
    );
  }

  @Post('summarize')
  @ApiOperation({
    summary: 'AI-advisory incident summary (Phase 10c)',
    description:
      "Gathers caller-specified context (an existing incidentId and/or explicit auditEventIds and/or free-text description -- all resolved against the caller's own tenant only) and calls manar-ai's SummarizeIncident RPC. Read-only: never persisted onto the Incident model. `available: false` means manar-ai was unreachable/timed out/circuit-open -- never a crash, never a fabricated summary.",
  })
  @ApiBody({ type: SummarizeIncidentRequestDto })
  @ApiResponse({ status: 201, type: SummarizeIncidentResponseDto })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({
    status: 404,
    type: ErrorResponseDto,
    description: 'incidentId was provided but not found in this tenant.',
  })
  async summarize(
    @CurrentAuth() auth: AuthContext,
    @Body() body: unknown,
  ): Promise<SummarizeIncidentResponseDto> {
    const input = parseBodyOrThrow(SummarizeIncidentSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return mapIncidentErrors(() =>
      this.incidentsService.summarizeIncident(tenantClient, {
        ...input,
        tenantId: auth.tenant.id,
      }),
    );
  }

  @Patch(':id')
  @ApiOperation({
    summary: 'Update an incident',
    description:
      'Partial update -- title/description/severity/status/relatedCorrelationIds. A status change is audited (incident.status_changed). Setting status to RESOLVED stamps resolvedAt.',
  })
  @ApiParam({ name: 'id', description: 'Incident ID', format: 'uuid' })
  @ApiBody({ type: UpdateIncidentRequestDto })
  @ApiResponse({ status: 200, type: IncidentSummaryDto })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({
    status: 404,
    type: ErrorResponseDto,
    description: 'Incident not found.',
  })
  async update(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
    @Body() body: unknown,
  ): Promise<IncidentSummaryDto> {
    const input = parseBodyOrThrow(UpdateIncidentSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return mapIncidentErrors(() =>
      this.incidentsService.updateIncident(tenantClient, {
        ...input,
        tenantId: auth.tenant.id,
        incidentId: id,
        actorUserId: auth.user.id,
      }),
    );
  }
}
