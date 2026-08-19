import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  ForbiddenException,
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
  ApiQuery,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { isRoleName, ROLES } from '../auth/roles';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import {
  parseCursor,
  parseLimit,
} from '../common/pagination/cursor-pagination';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import {
  PrivilegeEscalationError,
  TenantRealmNotProvisionedError,
  UserNotFoundError,
} from './users.errors';
import { UsersService } from './users.service';
import { GrantRoleRequestSchema } from './users.validation';
import {
  GrantRoleRequestDto,
  UserListResponseDto,
  UserSummaryDto,
} from './users.dto';

/** Translates `UsersService`'s typed domain errors into HTTP responses, keeping controller methods free of repeated try/catch (mirrors `AgentsController`'s identical `mapAgentNotFound` convention). */
async function mapUserErrors<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof UserNotFoundError) {
      throw new NotFoundException(error.message);
    }
    if (error instanceof PrivilegeEscalationError) {
      throw new ForbiddenException(error.message);
    }
    if (error instanceof TenantRealmNotProvisionedError) {
      throw new BadRequestException(error.message);
    }
    throw error;
  }
}

/**
 * `GET /users`/`GET /users/:id` — any authenticated tenant user may view
 * the roster (a teammate's role badges are not sensitive within the same
 * tenant, and `manar-web`'s `/users` page needs this for every viewer, not
 * just admins). `POST`/`DELETE .../role-bindings` — role management — is
 * gated to `TENANT_OWNER`/`SECURITY_ADMIN`, *and* additionally enforces a
 * privilege-escalation guard inside `UsersService.grantRole` (Phase 14's
 * design spec: a caller can never grant a role more privileged than any
 * role they themselves currently hold — see
 * `src/auth/role-privilege.ts`).
 */
@ApiTags('users')
@ApiBearerAuth('jwt')
@Controller('users')
@UseGuards(JwtAuthGuard, RolesGuard)
export class UsersController {
  constructor(
    private readonly usersService: UsersService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

  @Get()
  @ApiOperation({
    summary: "List users of the caller's tenant",
    description:
      'Cursor-paginated, newest first. Each row includes its current RoleBinding set. Any authenticated tenant user may call this.',
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
  @ApiResponse({ status: 200, type: UserListResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  async listUsers(
    @CurrentAuth() auth: AuthContext,
    @Query('limit') limit?: string,
    @Query('cursor') cursor?: string,
  ): Promise<UserListResponseDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return this.usersService.listUsers(tenantClient, {
      limit: parseLimit(limit),
      cursor: parseCursor(cursor),
    });
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get one user, including its current RoleBindings' })
  @ApiParam({ name: 'id', description: 'UserProfile ID', format: 'uuid' })
  @ApiResponse({ status: 200, type: UserSummaryDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({
    status: 404,
    type: ErrorResponseDto,
    description: 'User not found.',
  })
  async getUser(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
  ): Promise<UserSummaryDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return mapUserErrors(() =>
      this.usersService.getUserOrThrow(tenantClient, id),
    );
  }

  @Post(':id/role-bindings')
  @RequireRole('TENANT_OWNER', 'SECURITY_ADMIN')
  @ApiOperation({
    summary: 'Grant a role to a user',
    description:
      "Requires TENANT_OWNER or SECURITY_ADMIN, AND enforces a privilege-escalation guard: the caller can never grant a role more privileged than any role they themselves currently hold (e.g. a SECURITY_ADMIN can never grant TENANT_OWNER, including to themselves) -- see src/auth/role-privilege.ts. Also updates the underlying Keycloak realm role mapping (the role-assignment source of truth -- see docs/human-auth.md), not just the local RoleBinding row, so the grant survives the user's next JwtAuthGuard sync. Audited.",
  })
  @ApiParam({
    name: 'id',
    description: 'UserProfile ID of the user being granted a role',
    format: 'uuid',
  })
  @ApiBody({ type: GrantRoleRequestDto })
  @ApiResponse({ status: 201, type: UserSummaryDto })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({
    status: 403,
    type: ErrorResponseDto,
    description:
      'Caller lacks TENANT_OWNER/SECURITY_ADMIN, or the privilege-escalation guard rejected this grant.',
  })
  @ApiResponse({
    status: 404,
    type: ErrorResponseDto,
    description: 'User not found.',
  })
  async grantRole(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
    @Body() body: unknown,
  ): Promise<UserSummaryDto> {
    const input = parseBodyOrThrow(GrantRoleRequestSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return mapUserErrors(() =>
      this.usersService.grantRole(tenantClient, {
        tenantId: auth.tenant.id,
        targetUserId: id,
        role: input.role,
        grantedByUserId: auth.user.id,
        grantedByRoles: auth.roles,
      }),
    );
  }

  @Delete(':id/role-bindings/:role')
  @RequireRole('TENANT_OWNER', 'SECURITY_ADMIN')
  @ApiOperation({
    summary: 'Revoke a role from a user',
    description:
      "Requires TENANT_OWNER or SECURITY_ADMIN. Idempotent -- revoking a role the user doesn't currently hold succeeds as a no-op. Also updates the underlying Keycloak realm role mapping, not just the local RoleBinding row. Audited.",
  })
  @ApiParam({ name: 'id', description: 'UserProfile ID', format: 'uuid' })
  @ApiParam({ name: 'role', enum: ROLES })
  @ApiResponse({ status: 200, type: UserSummaryDto })
  @ApiResponse({
    status: 400,
    type: ErrorResponseDto,
    description: 'Unknown role.',
  })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({
    status: 404,
    type: ErrorResponseDto,
    description: 'User not found.',
  })
  async revokeRole(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
    @Param('role') role: string,
  ): Promise<UserSummaryDto> {
    if (!isRoleName(role)) {
      throw new BadRequestException(`Unknown role "${role}"`);
    }
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return mapUserErrors(() =>
      this.usersService.revokeRole(tenantClient, {
        tenantId: auth.tenant.id,
        targetUserId: id,
        role,
        revokedByUserId: auth.user.id,
      }),
    );
  }
}
