import { Controller, Get, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
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
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import { AuditService } from './audit.service';
import { VerifyAuditChainResponseDto } from './audit.dto';

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
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

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
    return this.auditService.verifyAuditChain(tenantClient);
  }
}
