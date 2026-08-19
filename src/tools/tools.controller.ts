import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiQuery,
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
import {
  parseCursor,
  parseLimit,
} from '../common/pagination/cursor-pagination';
import { ToolRegistryService } from './tool-registry.service';
import { ToolListResponseDto } from './tools.dto';

/**
 * Human-facing `GET /tools` (Phase 11b Part 1) — the first human-facing
 * endpoint for the `Tool`/`ToolAction` registry (Phase 7b built the
 * registry itself and `ToolRegistryService`'s read-only lookups, consumed
 * only by `CredentialBrokerService`/`RiskEngine` internally; there was no
 * HTTP surface for a human to browse it before this phase). Gated the
 * same `SECURITY_ADMIN`/`TENANT_OWNER`/`AI_GOVERNANCE_MANAGER` convention
 * `TasksController`/`PolicyController` use — a tool's registration and
 * enablement status is exactly the kind of security-relevant
 * configuration those roles already administer.
 *
 * List only, per this phase's explicit scope (Section 8's paginated list
 * endpoint requirement) — no `GET /tools/:id`, `POST /tools`, or other
 * tool-registry CRUD is added here; that's real scope this phase doesn't
 * ask for (`Tool` rows are created directly against the tenant database
 * by every e2e test fixture that needs one, matching this codebase's
 * existing "no HTTP endpoint for this yet" precedent for the registry).
 */
@ApiTags('tools')
@ApiBearerAuth('jwt')
@Controller('tools')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('SECURITY_ADMIN', 'TENANT_OWNER', 'AI_GOVERNANCE_MANAGER')
export class ToolsController {
  constructor(
    private readonly toolRegistryService: ToolRegistryService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

  @Get()
  @ApiOperation({
    summary: 'List registered tools',
    description:
      'Cursor-paginated, newest first, each row including its ToolAction rows. Optional `enabled` filter.',
  })
  @ApiQuery({ name: 'enabled', required: false, type: Boolean })
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
  @ApiResponse({ status: 200, type: ToolListResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async list(
    @CurrentAuth() auth: AuthContext,
    @Query('enabled') enabled?: string,
    @Query('limit') limit?: string,
    @Query('cursor') cursor?: string,
  ): Promise<ToolListResponseDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return this.toolRegistryService.list(tenantClient, {
      enabled:
        enabled === undefined
          ? undefined
          : enabled === 'true' || enabled === '1',
      limit: parseLimit(limit),
      cursor: parseCursor(cursor),
    });
  }
}
