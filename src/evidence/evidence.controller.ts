import { Body, Controller, HttpCode, Post, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import {
  EvidenceExportRequestSchema,
  EvidenceVerifyRequestSchema,
} from './evidence-export.validation';
import { EvidenceExportService } from './evidence-export.service';
import {
  EvidenceExportRequestDto,
  EvidenceExportResponseDto,
} from './evidence.dto';

/**
 * `POST /evidence/export` (Phase 9b, Section 49). JWT-guarded,
 * human-facing only, restricted to the three roles the design spec names —
 * the same `AUDITOR`/`SECURITY_ADMIN`/`TENANT_OWNER` gate `AuditController`
 * already uses for `GET /audit/verify`.
 */
@ApiTags('evidence')
@ApiBearerAuth('jwt')
@Controller('evidence')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('AUDITOR', 'SECURITY_ADMIN', 'TENANT_OWNER')
export class EvidenceController {
  constructor(
    private readonly evidenceExportService: EvidenceExportService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

  @Post('export')
  @ApiOperation({
    summary: 'Export a signed evidence bundle',
    description:
      'Gathers matching AuditEvents plus directly-relevant operational context (agents, tasks, delegations, policy versions, approvals, grants, tool invocations) into a signed/hashed bundle. At least one of since/until/agentId/taskId/correlationId is required.',
  })
  @ApiBody({ type: EvidenceExportRequestDto })
  @ApiResponse({ status: 201, type: EvidenceExportResponseDto })
  @ApiResponse({
    status: 400,
    type: ErrorResponseDto,
    description: 'No filter dimension provided, or invalid body.',
  })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async export(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const filter = parseBodyOrThrow(EvidenceExportRequestSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );

    return this.evidenceExportService.export(
      tenantClient,
      auth.tenant.id,
      auth.user.id,
      filter,
    );
  }

  @Post('verify')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Verify an exported evidence bundle',
    description:
      "Checks the signature and the bundle hash of a bundle returned by POST /evidence/export, then every event's inclusion proof against a checkpoint signed by the tenant's key. Returns { valid, proofsVerified, proofsMissing } or, when invalid, { valid: false, reason }.",
  })
  @ApiResponse({
    status: 200,
    description:
      "{ valid: true, proofsVerified: number, proofsMissing: number } | { valid: false, reason: string }. A missing proof is accepted only for an event of the caller's own tenant that no checkpoint covers yet; otherwise reason is proof_missing or proof_unverifiable.",
  })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  async verify(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const input = parseBodyOrThrow(EvidenceVerifyRequestSchema, body);
    const ownBundle =
      typeof input.bundle === 'object' &&
      input.bundle !== null &&
      (input.bundle as { tenantId?: unknown }).tenantId === auth.tenant.id;
    return this.evidenceExportService.verify(
      input.bundle,
      input.signature,
      ownBundle
        ? await this.tenantDatabaseManager.getClient(auth.tenant.id)
        : undefined,
    );
  }
}
