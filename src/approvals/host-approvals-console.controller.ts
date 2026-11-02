import { approvalMatchCode } from '../phone/phone-token';
import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  NotFoundException,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import {
  DecideHostApprovalSchema,
  RevokeApprovalSchema,
} from './approvals.validation';
import { explainRisk } from './risk-explain';
import { HostApprovalsService } from './host-approvals.service';
import { ApprovalRevokeService } from './approval-revoke.service';
import {
  APPROVER_ROLES,
  ApproverDirectory,
  choicesFor,
  type DeciderKind,
} from './approver-directory';

/**
 * Device approvals in the console: the same queue as WARDEN, plus the high-risk ones. Every member
 * may open it (founder decision, 3 Nov 2026): approvers see and decide everything, anyone else sees
 * and decides only their own devices' requests, unless the workspace is "admins only".
 * `HostApprovalsService.decide` enforces who may decide for every channel.
 */
@ApiTags('approvals')
@ApiBearerAuth('jwt')
@Controller('host-approvals')
@UseGuards(JwtAuthGuard, RolesGuard)
export class HostApprovalsConsoleController {
  constructor(
    private readonly approvals: HostApprovalsService,
    private readonly tenants: TenantDatabaseManager,
    private readonly approvers: ApproverDirectory,
    private readonly revokeService: ApprovalRevokeService,
  ) {}

  private isAdmin(auth: AuthContext): boolean {
    return auth.roles.some((r) =>
      (APPROVER_ROLES as readonly string[]).includes(r),
    );
  }

  /** What the person may do with their own devices' requests (admins: with any). */
  private async viewer(auth: AuthContext): Promise<DeciderKind | null> {
    if (this.isAdmin(auth)) return 'admin';
    return (await this.approvers.adminsOnly(auth.tenant.id)) ? null : 'owner';
  }

  @Get()
  @ApiOperation({ summary: 'Pending approvals opened by devices' })
  async list(@CurrentAuth() auth: AuthContext) {
    const client = await this.tenants.getClient(auth.tenant.id);
    await this.approvals.expireDue(client, auth.tenant.id);
    const viewer = await this.viewer(auth);
    const rows = await this.approvals.listPending(
      client,
      undefined,
      undefined,
      {
        ownerSubject:
          viewer === 'admin' ? undefined : auth.user.keycloakSubject,
      },
    );
    return {
      items: rows.map((r) => ({
        id: r.id,
        hostId: r.hostId,
        hostName: r.host.hostname,
        toolId: r.toolId,
        actionId: r.actionId,
        resource: r.resource,
        summary: r.summary,
        matchCode: approvalMatchCode(r.id),
        highRisk: r.highRisk,
        explanation: explainRisk(r.actionId, r.resource, r.highRisk),
        expiresAt: r.expiresAt,
        createdAt: r.createdAt,
        allowedDecisions: choicesFor(viewer, r),
      })),
    };
  }

  @Post(':id/decide')
  @ApiOperation({
    summary: 'Decide a device approval: approve_once, approve_8h or deny',
    description:
      '`makeRule` returns a pre-filled policy rule for the rule editor. Approvers decide anything; the device owner may approve once or deny their own device\'s requests unless the workspace is "admins only".',
  })
  async decide(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
    @Body() body: unknown,
  ) {
    const input = parseBodyOrThrow(DecideHostApprovalSchema, body);
    const client = await this.tenants.getClient(auth.tenant.id);
    return this.approvals.decide(client, auth.tenant.id, {
      approvalId: id,
      subject: auth.user.keycloakSubject,
      decision: input.decision,
      via: 'console',
      // makeRule pre-fills a policy rule: an approver's call.
      makeRule: input.makeRule && this.isAdmin(auth),
      // A permanent site rule needs the role that may write site rules in the console.
      canWriteSiteRules: auth.roles.some(
        (r) => r === 'TENANT_OWNER' || r === 'SECURITY_ADMIN',
      ),
    });
  }

  @Post(':id/revoke')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Revoke a device approval given by mistake',
    description:
      'Not yet read by the device: cancelled at once and the device sees REVOKED. Already read: marked revoked after use, the admins are alerted and the same action is blocked (for a site: a DENY site rule) until someone lifts it. Any 8-hour grant or remembered site rule it created is withdrawn.',
  })
  async revoke(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
    @Body() body: unknown,
  ) {
    const input = parseBodyOrThrow(RevokeApprovalSchema, body ?? {});
    const client = await this.tenants.getClient(auth.tenant.id);
    const row = await client.hostApproval.findUnique({
      where: { id },
      select: { host: { select: { ownerSubject: true } } },
    });
    const own = row?.host.ownerSubject === auth.user.keycloakSubject;
    if (!row || (!this.isAdmin(auth) && !own))
      throw new NotFoundException('That approval was not found.');
    if (!(await this.viewer(auth)))
      throw new ForbiddenException(
        'Only a workspace approver can revoke this approval. Nothing was changed.',
      );
    return this.revokeService.revokeHost(
      client,
      auth.tenant.id,
      id,
      { userId: auth.user.id, subject: auth.user.keycloakSubject },
      input.note,
    );
  }
}
