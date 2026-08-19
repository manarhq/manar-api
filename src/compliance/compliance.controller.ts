import {
  Controller,
  Get,
  NotFoundException,
  Param,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import { ComplianceFrameworkNotFoundError } from './compliance.errors';
import { ComplianceService } from './compliance.service';
import {
  ComplianceControlListResponseDto,
  ComplianceFrameworkListResponseDto,
} from './compliance.dto';

/** Translates `ComplianceService`'s typed domain errors into HTTP responses — mirrors `UsersController`'s identical `mapUserErrors` convention. */
async function mapComplianceErrors<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof ComplianceFrameworkNotFoundError) {
      throw new NotFoundException(error.message);
    }
    throw error;
  }
}

/**
 * Phase 15a (Section 55) — `GET /compliance/frameworks` and `GET
 * /compliance/frameworks/:id/controls`, surfacing this codebase's own
 * honest, researched compliance-control mapping (ISO/IEC 27001:2022 +
 * NIST AI RMF 1.0 subsets, seeded by this phase's own migration — see
 * docs/compliance-mapping.md). Read-only, reference-data-only: JWT-guarded
 * only, no role restriction (mirrors `UsersController`'s "a teammate's
 * data is not sensitive within the same tenant" posture — this is even
 * less sensitive, since it's identical, non-tenant-specific product
 * content, not per-user data).
 *
 * **Never returns certification language.** `ComplianceMappingSummaryDto.status`
 * is one of Section 55's four honest self-assessment statuses
 * (`MAPPED`/`EVIDENCE_AVAILABLE`/`PARTIALLY_IMPLEMENTED`/`NOT_EVALUATED`) —
 * there is no fifth "CERTIFIED" value anywhere in this surface, by design.
 */
@ApiTags('compliance')
@ApiBearerAuth('jwt')
@Controller('compliance')
@UseGuards(JwtAuthGuard)
export class ComplianceController {
  constructor(
    private readonly complianceService: ComplianceService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

  @Get('frameworks')
  @ApiOperation({
    summary: 'List compliance frameworks this codebase maps against',
    description:
      'Currently ISO/IEC 27001:2022 and NIST AI RMF 1.0 — a representative subset, not exhaustive coverage of either standard. See docs/compliance-mapping.md.',
  })
  @ApiResponse({ status: 200, type: ComplianceFrameworkListResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  async listFrameworks(
    @CurrentAuth() auth: AuthContext,
  ): Promise<ComplianceFrameworkListResponseDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    const items = await this.complianceService.listFrameworks(tenantClient);
    return { items };
  }

  @Get('frameworks/:id/controls')
  @ApiOperation({
    summary: "List one framework's mapped controls",
    description:
      'Each control includes its current mapping status/evidence — an honest self-assessment, never a certification claim.',
  })
  @ApiParam({
    name: 'id',
    description: 'ComplianceFramework ID',
    format: 'uuid',
  })
  @ApiResponse({ status: 200, type: ComplianceControlListResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({
    status: 404,
    type: ErrorResponseDto,
    description: 'Framework not found.',
  })
  async listControls(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
  ): Promise<ComplianceControlListResponseDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    const items = await mapComplianceErrors(() =>
      this.complianceService.listControls(tenantClient, id),
    );
    return { items };
  }
}
