import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { approvalMatchCode } from '../phone/phone-token';
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
import { dbNow } from '../common/db-clock';
import { isWorkspacePaused } from '../pause/pause-state';
import { explainRisk } from './risk-explain';
import { HostApprovalsService, publicOffer } from './host-approvals.service';

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
    await this.approvals.expireDue(client, host.tenantId);
    const [ownerMayApprove, rows] = await Promise.all([
      // The device decides only for an owner who is an approver: anyone else answers in the
      // signed-in console (a process on the device can answer a device prompt).
      this.approvers.canApprove(host.tenantId, client, host.ownerSubject),
      this.approvals.listPending(client, host.hostId),
    ]);
    const offers = await this.approvals.offersFor(client, rows);
    return {
      ownerMayApprove,
      items: rows.map((r) => ({
        id: r.id,
        toolId: r.toolId,
        actionId: r.actionId,
        resource: r.resource,
        summary: r.summary,
        matchCode: approvalMatchCode(r.id),
        highRisk: r.highRisk,
        explanation: explainRisk(r.actionId, r.resource, r.highRisk),
        // "Always allow this here" (answered in the console; WARDEN shows it as a hint).
        ruleOffer: publicOffer(offers.get(r.id)),
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
    await this.approvals.expireDue(client, host.tenantId);
    // While AI is paused an APPROVED answer does not run, so reading it is not a use.
    const paused = await isWorkspacePaused(client);
    const row = paused
      ? await this.approvals.get(client, id, host.hostId)
      : await this.approvals.readForDevice(client, id, host.hostId);
    const expired =
      row.status === 'PENDING' && row.expiresAt <= (await dbNow(client));
    const status = expired ? 'EXPIRED' : row.status;
    return {
      id: row.id,
      status,
      decision: row.decision,
      // The hook tells the agent "denied: no answer"; REVOKED: a person withdrew the approval.
      reason:
        status === 'EXPIRED'
          ? (row.endReason ?? 'no_answer')
          : status === 'REVOKED'
            ? 'revoked'
            : null,
      // "paused": AI is paused, so an APPROVED answer that landed anyway must not let the call run.
      paused,
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
    // Who may decide (an approver owner, routine requests only) is checked in
    // HostApprovalsService.decide.
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
      withdraw: input.withdraw,
    });
    return { id: result.id, status: result.status, decision: result.decision };
  }
}
