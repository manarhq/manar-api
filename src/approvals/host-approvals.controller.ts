import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { ApiExcludeController } from '@nestjs/swagger';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { HostAuthGuard } from '../host-mtls/host-auth.guard';
import { CurrentHost, type HostContext } from '../host-mtls/host-context';
import { SITE_CONNECT_ACTION } from '../jail/jail-sites';
import { ApproverDirectory } from './approver-directory';
import {
  DecideHostApprovalSchema,
  VaultRequestSchema,
} from './approvals.validation';
import { HostApprovalsService } from './host-approvals.service';

/**
 * `/host/v1/approvals/*`: what WARDEN on a device reads and answers (spec 4.6). A decision from a
 * device is bound to the host's owner: allowed only when that person may approve in this
 * workspace (a personal workspace's owner, or someone with an approver role), only for a host that
 * is already APPROVED, and never for a high-risk action ("open in console").
 */
@ApiExcludeController()
@Controller('host/v1/approvals')
@UseGuards(HostAuthGuard)
export class HostApprovalsController {
  constructor(
    private readonly approvals: HostApprovalsService,
    private readonly tenants: TenantDatabaseManager,
    private readonly approvers: ApproverDirectory,
  ) {}

  @Get('pending')
  async pending(@CurrentHost() host: HostContext) {
    if (host.status !== 'APPROVED')
      return { items: [], ownerMayApprove: false };
    const client = await this.tenants.getClient(host.tenantId);
    const [ownerMayApprove, rows] = await Promise.all([
      this.approvers.canApprove(host.tenantId, client, host.ownerSubject),
      this.approvals.listPending(client, host.hostId),
    ]);
    return {
      ownerMayApprove,
      items: rows.map((r) => ({
        id: r.id,
        toolId: r.toolId,
        actionId: r.actionId,
        resource: r.resource,
        summary: r.summary,
        highRisk: r.highRisk,
        // The prompt shows buttons only when this is true; otherwise "Open in console".
        decidableHere:
          ownerMayApprove &&
          !r.highRisk &&
          // a new site is answered in the console or on the phone
          r.actionId !== SITE_CONNECT_ACTION,
        expiresAt: r.expiresAt,
        createdAt: r.createdAt,
      })),
    };
  }

  /** The secrets vault: a program asks to use a secret. Decided in the console only. */
  @Post('vault')
  async vault(@CurrentHost() host: HostContext, @Body() body: unknown) {
    const input = parseBodyOrThrow(VaultRequestSchema, body);
    if (host.status !== 'APPROVED')
      throw new ForbiddenException('device_not_approved');
    const client = await this.tenants.getClient(host.tenantId);
    const row = await this.approvals.openSecretUse(client, host.tenantId, {
      hostId: host.hostId,
      program: input.program,
      secretName: input.secret,
    });
    return { id: row.id, expiresAt: row.expiresAt };
  }

  /** The hook polls this for the answer. */
  @Get(':id')
  async status(@CurrentHost() host: HostContext, @Param('id') id: string) {
    const client = await this.tenants.getClient(host.tenantId);
    const row = await this.approvals.get(client, id, host.hostId);
    const expired = row.status === 'PENDING' && row.expiresAt <= new Date();
    return {
      id: row.id,
      status: expired ? 'EXPIRED' : row.status,
      decision: row.decision,
    };
  }

  @Post(':id/decide')
  async decide(
    @CurrentHost() host: HostContext,
    @Param('id') id: string,
    @Body() body: unknown,
  ) {
    const input = parseBodyOrThrow(DecideHostApprovalSchema, body);
    if (host.status !== 'APPROVED' || !host.ownerSubject) {
      throw new ForbiddenException('device_not_allowed_to_decide');
    }
    const client = await this.tenants.getClient(host.tenantId);
    if (
      !(await this.approvers.canApprove(
        host.tenantId,
        client,
        host.ownerSubject,
      ))
    ) {
      throw new ForbiddenException('owner_is_not_an_approver');
    }
    const row = await this.approvals.get(client, id, host.hostId);
    if (row.highRisk) throw new ForbiddenException('high_risk_open_in_console');
    if (row.actionId === SITE_CONNECT_ACTION && input.decision !== 'deny')
      throw new ForbiddenException('site_in_console');
    const result = await this.approvals.decide(client, host.tenantId, {
      approvalId: id,
      hostId: host.hostId,
      subject: host.ownerSubject,
      decision: input.decision,
      via: 'device',
    });
    return { id: result.id, status: result.status, decision: result.decision };
  }
}
