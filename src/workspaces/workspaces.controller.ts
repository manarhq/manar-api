import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { CurrentAuth, type AuthContext } from '../auth/auth-context';
import { CurrentIdentity, IdentityGuard } from '../auth/identity.guard';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { canGrantRole } from '../auth/role-privilege';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import type { VerifiedIdentity } from '../auth/token-verifier.service';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import { ControlPrismaService } from '../database/control-prisma.service';
import {
  CompanyForMeResponseDto,
  CompanyTrialRequestDto,
  CompanyTrialRequestSchema,
  CreateWorkspaceResponseDto,
  DecideJoinRequestDto,
  DecideJoinRequestSchema,
  JoinRequestListResponseDto,
  JoinRequestRespondDto,
  MeResponseDto,
  SwitchWorkspaceRequestDto,
  SwitchWorkspaceRequestSchema,
  WorkspaceListResponseDto,
  WorkspaceSummaryDto,
} from './workspaces.dto';
import { WorkspacesService } from './workspaces.service';

/**
 * Workspace endpoints that work before a workspace exists (`IdentityGuard`: a verified token and
 * nothing else). None takes a tenant id from the caller except `switch`, which only validates it
 * against the caller's own Memberships.
 */
@ApiTags('workspaces')
@ApiBearerAuth('jwt')
@Controller('workspaces')
@UseGuards(IdentityGuard)
export class WorkspacesController {
  constructor(private readonly workspaces: WorkspacesService) {}

  @Get()
  @ApiOperation({ summary: "The caller's workspaces (switcher, setup state)" })
  @ApiResponse({ status: 200, type: WorkspaceListResponseDto })
  async list(
    @CurrentIdentity() id: VerifiedIdentity,
  ): Promise<WorkspaceListResponseDto> {
    return { items: await this.workspaces.list(id.subject) };
  }

  @Post('bootstrap')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Create the personal workspace on first sign-in (idempotent)',
    description:
      'QUEUED means capacity was low: the workspace is set up in the background.',
  })
  @ApiResponse({ status: 200, type: CreateWorkspaceResponseDto })
  bootstrap(@CurrentIdentity() id: VerifiedIdentity) {
    return this.workspaces.ensurePersonal(id);
  }

  @Post('switch')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Validate a workspace choice',
    description:
      'The choice itself lives in the web session and travels as X-Manar-Workspace; every request is checked against Membership again.',
  })
  @ApiResponse({ status: 200, type: WorkspaceSummaryDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  switch(
    @CurrentIdentity() id: VerifiedIdentity,
    @Body() body: SwitchWorkspaceRequestDto,
  ) {
    const input = parseBodyOrThrow(SwitchWorkspaceRequestSchema, body);
    return this.workspaces.assertSwitchable(id.subject, input.tenantId);
  }

  @Get('company')
  @ApiOperation({
    summary:
      "Is there a company workspace for the caller's Microsoft organisation?",
  })
  @ApiResponse({ status: 200, type: CompanyForMeResponseDto })
  company(@CurrentIdentity() id: VerifiedIdentity) {
    return this.workspaces.companyForMe(id);
  }

  @Post('company')
  @ApiOperation({
    summary: 'Start a company trial (Entra admin only)',
    description:
      'Needs a work account whose token carries Global Administrator or Privileged Role Administrator in `wids`.',
  })
  @ApiResponse({ status: 201, type: CreateWorkspaceResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({
    status: 409,
    type: ErrorResponseDto,
    description: 'Your organisation already has a workspace: request to join.',
  })
  startTrial(
    @CurrentIdentity() id: VerifiedIdentity,
    @Body() body: CompanyTrialRequestDto,
  ) {
    const input = parseBodyOrThrow(CompanyTrialRequestSchema, body);
    return this.workspaces.startCompanyTrial(id, input.displayName);
  }

  @Post('company/join-requests')
  @ApiOperation({
    summary: 'Ask to join the company workspace of your organisation',
    description: 'Never joins automatically; a workspace admin approves.',
  })
  @ApiResponse({ status: 201, type: JoinRequestRespondDto })
  requestToJoin(@CurrentIdentity() id: VerifiedIdentity) {
    return this.workspaces.requestToJoin(id);
  }
}

/** Workspace admin side and `GET /me`: these need a resolved workspace (`JwtAuthGuard`). */
@ApiTags('workspaces')
@ApiBearerAuth('jwt')
@Controller()
@UseGuards(JwtAuthGuard, RolesGuard)
export class CurrentWorkspaceController {
  constructor(
    private readonly workspaces: WorkspacesService,
    private readonly control: ControlPrismaService,
  ) {}

  @Get('me')
  @ApiOperation({
    summary: 'The caller, the active workspace and the roles held in it',
  })
  @ApiResponse({ status: 200, type: MeResponseDto })
  async me(@CurrentAuth() auth: AuthContext): Promise<MeResponseDto> {
    const tenant = await this.control.tenant.findUniqueOrThrow({
      where: { id: auth.tenant.id },
    });
    return {
      subject: auth.user.keycloakSubject,
      email: auth.user.email,
      displayName: auth.user.displayName,
      workspace: { id: tenant.id, name: tenant.name, kind: tenant.kind },
      roles: auth.roles,
    };
  }

  @Get('workspaces/current/join-requests')
  @RequireRole('TENANT_OWNER', 'SECURITY_ADMIN')
  @ApiOperation({ summary: 'Pending requests to join this company workspace' })
  @ApiResponse({ status: 200, type: JoinRequestListResponseDto })
  async joinRequests(
    @CurrentAuth() auth: AuthContext,
  ): Promise<JoinRequestListResponseDto> {
    return { items: await this.workspaces.listJoinRequests(auth.tenant.id) };
  }

  @Post('workspaces/current/join-requests/:membershipId/approve')
  @RequireRole('TENANT_OWNER', 'SECURITY_ADMIN')
  @HttpCode(204)
  @ApiOperation({
    summary:
      'Approve a join request (default role DEVELOPER; never above your own)',
  })
  async approve(
    @CurrentAuth() auth: AuthContext,
    @Param('membershipId') membershipId: string,
    @Body() body: DecideJoinRequestDto,
  ): Promise<void> {
    const { role } = parseBodyOrThrow(DecideJoinRequestSchema, body ?? {});
    if (role && !canGrantRole(auth.roles, role)) {
      throw new ForbiddenException('Cannot grant a role above your own');
    }
    await this.workspaces.decideJoinRequest(
      auth.tenant.id,
      membershipId,
      'approve',
      auth.user.keycloakSubject,
      role,
    );
  }

  @Post('workspaces/current/join-requests/:membershipId/reject')
  @RequireRole('TENANT_OWNER', 'SECURITY_ADMIN')
  @HttpCode(204)
  @ApiOperation({ summary: 'Reject a join request' })
  async reject(
    @CurrentAuth() auth: AuthContext,
    @Param('membershipId') membershipId: string,
  ): Promise<void> {
    await this.workspaces.decideJoinRequest(
      auth.tenant.id,
      membershipId,
      'reject',
      auth.user.keycloakSubject,
    );
  }
}
