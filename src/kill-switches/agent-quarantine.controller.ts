import {
  Body,
  Controller,
  Get,
  NotFoundException,
  Param,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiParam,
  ApiProperty,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { z } from 'zod';
import type { AgentQuarantine } from '../generated/tenant-client/client';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { AgentQuarantineService } from './agent-quarantine.service';

const ReleaseQuarantineRequestSchema = z
  .object({ note: z.string().trim().min(1).max(500).optional() })
  .strict();

export class ReleaseQuarantineRequestDto {
  @ApiProperty({ required: false, maxLength: 500 })
  note?: string;
}

export class AgentQuarantineDto {
  @ApiProperty({ format: 'uuid' }) id!: string;
  @ApiProperty({ format: 'uuid' }) agentId!: string;
  @ApiProperty() active!: boolean;
  @ApiProperty({
    description: 'Deterministic reason from the detector that fired.',
  })
  reason!: string;
  @ApiProperty({ nullable: true }) detector!: string | null;
  @ApiProperty({
    type: [String],
    description: 'Evidence ids (decisions, audit events).',
  })
  evidence!: string[];
  @ApiProperty({
    nullable: true,
    description:
      'Model-written explanation (English). Generated, not verified.',
  })
  explanationEn!: string | null;
  @ApiProperty({
    nullable: true,
    description: 'Model-written explanation (Arabic). Generated, not verified.',
  })
  explanationAr!: string | null;
  @ApiProperty({
    format: 'uuid',
    description: 'The agent that quarantined (the watcher).',
  })
  quarantinedByAgentId!: string;
  @ApiProperty({ nullable: true, format: 'uuid' }) decisionId!: string | null;
  @ApiProperty({ format: 'date-time' }) quarantinedAt!: Date;
  @ApiProperty({
    nullable: true,
    description: 'UserProfile id of the human who released it.',
  })
  releasedBy!: string | null;
  @ApiProperty({ nullable: true, format: 'date-time' })
  releasedAt!: Date | null;
  @ApiProperty({ nullable: true }) releaseNote!: string | null;
}

export class AgentQuarantineListResponseDto {
  @ApiProperty({ type: [AgentQuarantineDto] })
  items!: AgentQuarantineDto[];
}

function toDto(row: AgentQuarantine): AgentQuarantineDto {
  return {
    id: row.id,
    agentId: row.agentId,
    active: row.active,
    reason: row.reason,
    detector: row.detector,
    evidence: Array.isArray(row.evidence) ? (row.evidence as string[]) : [],
    explanationEn: row.explanationEn,
    explanationAr: row.explanationAr,
    quarantinedByAgentId: row.quarantinedByAgentId,
    decisionId: row.decisionId,
    quarantinedAt: row.quarantinedAt,
    releasedBy: row.releasedBy,
    releasedAt: row.releasedAt,
    releaseNote: row.releaseNote,
  };
}

/**
 * ADR-0009: the human side of quarantine. Agents cannot reach this
 * controller (it lives on the JWT app, not the mTLS listener), and there is
 * no agent action that releases. Same roles as the kill switches.
 */
@ApiTags('kill-switches')
@ApiBearerAuth('jwt')
@Controller()
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('SECURITY_ADMIN', 'TENANT_OWNER')
export class AgentQuarantineController {
  constructor(
    private readonly quarantineService: AgentQuarantineService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

  @Get('quarantines')
  @ApiOperation({
    summary: 'List agent quarantines',
    description: 'Newest first, at most 100. Optional `active` filter.',
  })
  @ApiQuery({ name: 'active', required: false, type: Boolean })
  @ApiResponse({ status: 200, type: AgentQuarantineListResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async list(
    @CurrentAuth() auth: AuthContext,
    @Query('active') active?: string,
  ): Promise<AgentQuarantineListResponseDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    const rows = await this.quarantineService.list(
      tenantClient,
      active === undefined ? undefined : active === 'true' || active === '1',
    );
    return { items: rows.map(toDto) };
  }

  @Post('agents/:id/quarantine/release')
  @ApiOperation({
    summary: "Release an agent's quarantine (humans only)",
    description:
      'Loosening always needs a human. Audited as agent.quarantine_released with the releasing user. If the audit event cannot be written the release is undone (503).',
  })
  @ApiParam({ name: 'id', description: 'Agent ID', format: 'uuid' })
  @ApiBody({ type: ReleaseQuarantineRequestDto })
  @ApiResponse({ status: 201, type: AgentQuarantineDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  async release(
    @CurrentAuth() auth: AuthContext,
    @Param('id') agentId: string,
    @Body() body: unknown,
  ): Promise<AgentQuarantineDto> {
    const input = parseBodyOrThrow(ReleaseQuarantineRequestSchema, body ?? {});
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    const row = await this.quarantineService.release(
      tenantClient,
      auth.tenant.id,
      { agentId, releasedBy: auth.user.id, note: input.note },
    );
    if (!row) {
      throw new NotFoundException(
        `Agent "${agentId}" has no active quarantine`,
      );
    }
    return toDto(row);
  }
}
