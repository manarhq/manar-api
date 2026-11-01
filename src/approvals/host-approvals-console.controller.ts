import { approvalMatchCode } from '../phone/phone-token';
import { Body, Controller, Get, Param, Post, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { DecideHostApprovalSchema } from './approvals.validation';
import { explainRisk } from './risk-explain';
import { HostApprovalsService } from './host-approvals.service';

/** Device approvals in the console: the same queue as WARDEN, plus the high-risk ones. */
@ApiTags('approvals')
@ApiBearerAuth('jwt')
@Controller('host-approvals')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('APPROVER', 'SECURITY_ADMIN', 'TENANT_OWNER')
export class HostApprovalsConsoleController {
  constructor(
    private readonly approvals: HostApprovalsService,
    private readonly tenants: TenantDatabaseManager,
  ) {}

  @Get()
  @ApiOperation({ summary: 'Pending approvals opened by devices' })
  async list(@CurrentAuth() auth: AuthContext) {
    const client = await this.tenants.getClient(auth.tenant.id);
    await this.approvals.expireDue(client, auth.tenant.id);
    const rows = await this.approvals.listPending(client, undefined);
    return {
      items: rows.map((r) => ({
        id: r.id,
        hostId: r.hostId,
        toolId: r.toolId,
        actionId: r.actionId,
        resource: r.resource,
        summary: r.summary,
        matchCode: approvalMatchCode(r.id),
        highRisk: r.highRisk,
        explanation: explainRisk(r.actionId, r.resource, r.highRisk),
        expiresAt: r.expiresAt,
        createdAt: r.createdAt,
      })),
    };
  }

  @Post(':id/decide')
  @ApiOperation({
    summary: 'Decide a device approval: approve_once, approve_8h or deny',
    description:
      '`makeRule` returns a pre-filled policy rule for the rule editor.',
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
      makeRule: input.makeRule,
      // A permanent site rule needs the role that may write site rules in the console.
      canWriteSiteRules: auth.roles.some(
        (r) => r === 'TENANT_OWNER' || r === 'SECURITY_ADMIN',
      ),
    });
  }
}
