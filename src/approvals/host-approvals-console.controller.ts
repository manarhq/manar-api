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
import { pathDiffers } from './rule-scope';
import { HostApprovalsService, publicOffer } from './host-approvals.service';
import { ApprovalRevokeService } from './approval-revoke.service';
import {
  ApproverDirectory,
  isApproverRole,
  isOperatorRole,
} from './approver-directory';
import {
  decisionRights,
  freshSignIn,
  sensitiveReason,
  type DecisionRights,
} from './decision-rights';

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

  /**
   * What the person may do with one device's request. The owner path needs a role that may operate
   * devices now (a demoted or removed owner has none), and covers routine requests only.
   */
  private async rights(
    auth: AuthContext,
    row: {
      actionId: string;
      highRisk: boolean;
      host: { ownerSubject: string | null };
    },
    ws?: { adminsOnly: boolean; company: boolean },
  ): Promise<DecisionRights> {
    const w = ws ?? (await this.approvers.workspace(auth.tenant.id));
    return decisionRights({
      admin: isApproverRole(auth.roles),
      owner:
        row.host.ownerSubject === auth.user.keycloakSubject &&
        isOperatorRole(auth.roles),
      adminsOnly: w.adminsOnly,
      company: w.company,
      sensitive: sensitiveReason(row),
      actionId: row.actionId,
    });
  }

  @Get()
  @ApiOperation({ summary: 'Pending approvals opened by devices' })
  async list(@CurrentAuth() auth: AuthContext) {
    const admin = isApproverRole(auth.roles);
    // Not an approver and no role that operates devices: nothing to see.
    if (!admin && !isOperatorRole(auth.roles)) return { items: [] };
    const client = await this.tenants.getClient(auth.tenant.id);
    await this.approvals.expireDue(client, auth.tenant.id);
    const rows = await this.approvals.listPending(
      client,
      undefined,
      undefined,
      {
        ownerSubject: admin ? undefined : auth.user.keycloakSubject,
      },
    );
    const ws = await this.approvers.workspace(auth.tenant.id);
    const rights = await Promise.all(rows.map((r) => this.rights(auth, r, ws)));
    const offers = await this.approvals.offersFor(client, rows);
    // "Cursor on Sara's laptop wants to ...": the owner's name, never their subject.
    const owners = [
      ...new Set(
        rows.flatMap((r) => (r.host.ownerSubject ? [r.host.ownerSubject] : [])),
      ),
    ];
    const people = owners.length
      ? await client.userProfile.findMany({
          where: { keycloakSubject: { in: owners } },
          select: { keycloakSubject: true, displayName: true },
        })
      : [];
    const ownerName = new Map(
      people.map((p) => [p.keycloakSubject, p.displayName]),
    );
    return {
      items: rows.map((r, i) => ({
        id: r.id,
        hostId: r.hostId,
        hostName: r.host.hostname,
        ownerName: r.host.ownerSubject
          ? (ownerName.get(r.host.ownerSubject) ?? null)
          : null,
        toolId: r.toolId,
        actionId: r.actionId,
        resource: r.resource,
        // Where the file really points, when that is somewhere else: "points to ..." on the card.
        pointsTo:
          r.resolvedPath &&
          pathDiffers(r.toolId, r.actionId, r.resource, r.resolvedPath)
            ? r.resolvedPath
            : null,
        summary: r.summary,
        matchCode: approvalMatchCode(r.id),
        highRisk: r.highRisk,
        explanation: explainRisk(r.actionId, r.resource, r.highRisk),
        // "Always allow this here" after the 3rd identical approval; null when not offered.
        ruleOffer: publicOffer(offers.get(r.id)),
        expiresAt: r.expiresAt,
        createdAt: r.createdAt,
        allowedDecisions: rights[i]!.choices,
        needs: rights[i]!.needs,
        why: rights[i]!.why,
        // Approving needs a fresh sign-in first (personal workspace, own sensitive request).
        stepUpNeeded: rights[i]!.stepUp && !freshSignIn(auth.authTime),
      })),
    };
  }

  @Post(':id/decide')
  @ApiOperation({
    summary: 'Decide a device approval: approve_once, approve_8h or deny',
    description:
      '`makeRule` returns a pre-filled policy rule for the rule editor (approvers only). Approvers decide anything except a sensitive request from their own device; the device owner approves once or denies their own routine requests unless the workspace is "admins only".',
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
      makeRule: input.makeRule && isApproverRole(auth.roles),
      alwaysAllowHere: input.alwaysAllowHere,
      ownerMayOperate: isOperatorRole(auth.roles),
      freshSignIn: freshSignIn(auth.authTime),
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
      select: {
        actionId: true,
        highRisk: true,
        host: { select: { ownerSubject: true } },
      },
    });
    const visible =
      row !== null &&
      (isApproverRole(auth.roles) ||
        (row.host.ownerSubject === auth.user.keycloakSubject &&
          isOperatorRole(auth.roles)));
    if (!row || !visible)
      throw new NotFoundException('That approval was not found.');
    if (!(await this.rights(auth, row)).canRevoke)
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
