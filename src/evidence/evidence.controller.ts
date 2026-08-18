import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { EvidenceExportRequestSchema } from './evidence-export.validation';
import { EvidenceExportService } from './evidence-export.service';

/**
 * `POST /evidence/export` (Phase 9b, Section 49). JWT-guarded,
 * human-facing only, restricted to the three roles the design spec names —
 * the same `AUDITOR`/`SECURITY_ADMIN`/`TENANT_OWNER` gate `AuditController`
 * already uses for `GET /audit/verify`.
 */
@Controller('evidence')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('AUDITOR', 'SECURITY_ADMIN', 'TENANT_OWNER')
export class EvidenceController {
  constructor(
    private readonly evidenceExportService: EvidenceExportService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

  @Post('export')
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
}
