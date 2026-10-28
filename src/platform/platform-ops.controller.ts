import {
  Body,
  ConflictException,
  Controller,
  Get,
  HttpCode,
  Logger,
  Optional,
  Param,
  ParseUUIDPipe,
  Post,
  Req,
  UseGuards,
  Inject,
  forwardRef,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiProperty,
  ApiPropertyOptional,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { z } from 'zod';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import {
  AUDIT_EVENT_TYPES,
  type AuditEventType,
} from '../audit/audit-event-types';
import { ControlPrismaService } from '../database/control-prisma.service';
import { PlatformKillSwitchService } from '../kill-switches/platform-kill-switch.service';
import { KillSwitchEpochService } from '../kill-switches/kill-switch-epoch.service';
import {
  PlatformAuthGuard,
  type RequestWithPlatformCaller,
} from './platform-auth.guard';
import { PlatformOpsService } from './platform-ops.service';
import { EdgePeerService } from '../edge/edge-peer.service';

const staff = z.string().trim().min(1).max(200);
export const EngageSchema = z.object({
  reason: z.string().trim().min(3).max(500),
  staff,
});
export const ReleaseSchema = z.object({
  staff,
  proposedBy: staff.optional(),
  /** The engagement the release was proposed for; any other engagement stays on. */
  expectedEngagementId: z.iso.datetime(),
});

class EngageDto {
  @ApiProperty() reason!: string;
  @ApiProperty({ description: 'Staff member, recorded as the activator' })
  staff!: string;
}
class ReleaseDto {
  @ApiProperty() staff!: string;
  @ApiPropertyOptional() proposedBy?: string;
  @ApiProperty({ description: 'engagementId from GET /kill-switch' })
  expectedEngagementId!: string;
}
class KillSwitchStateDto {
  @ApiProperty() active!: boolean;
  @ApiProperty({
    nullable: true,
    type: String,
    description:
      'Identifies one engagement (its activation time); null while off',
  })
  engagementId!: string | null;
  @ApiProperty({ nullable: true, type: String }) reason!: string | null;
  @ApiProperty({ nullable: true, type: String }) activatedBy!: string | null;
  @ApiProperty({ nullable: true, type: Date }) activatedAt!: Date | null;
  @ApiProperty({ nullable: true, type: String }) deactivatedBy!: string | null;
  @ApiProperty({ nullable: true, type: Date }) deactivatedAt!: Date | null;
}
class TenantOpsDto {
  @ApiProperty({ description: 'Active kill switches with who and when' })
  killSwitches!: object[];
  @ApiProperty({
    description: 'Active quarantines and those released in the last 30 days',
  })
  quarantines!: object[];
  @ApiProperty({
    description: '{months: [{month, decisions}], agentsEnrolled, agentsTotal}',
  })
  usage!: object;
  @ApiProperty({
    description: 'Tools with the expiry recorded for their credential',
  })
  credentials!: object[];
}
class AuditVerifyDto {
  @ApiProperty() valid!: boolean;
  @ApiProperty() eventCount!: number;
  @ApiProperty({ nullable: true, type: String }) brokenAt!: string | null;
  @ApiProperty() verifiedAt!: string;
}

const caller = (req: RequestWithPlatformCaller) =>
  req.platformCaller?.clientId ?? 'unknown';
const SINGLETON = 'singleton';

type SwitchRow = {
  active: boolean;
  reason: string | null;
  activatedBy: string | null;
  activatedAt: Date | null;
  deactivatedBy: string | null;
  deactivatedAt: Date | null;
};
const view = (r: SwitchRow) => ({
  active: r.active,
  engagementId: r.active && r.activatedAt ? r.activatedAt.toISOString() : null,
  reason: r.reason,
  activatedBy: r.activatedBy,
  activatedAt: r.activatedAt,
  deactivatedBy: r.deactivatedBy,
  deactivatedAt: r.deactivatedAt,
});

/**
 * The deployment's platform kill switch for manar-fleet (admin v2). Same row and same effect as
 * `POST /kill-switches/platform`: every tenant's agents are denied on the decision path. Who may
 * engage or release is decided in manar-fleet (owner engages at once; a release is approved by a
 * second person). A release names the engagement it ends and is applied with one conditional
 * update, so a proposal made for an earlier engagement can never end a later one.
 */
@ApiTags('platform')
@ApiBearerAuth('platform')
@UseGuards(PlatformAuthGuard)
@Controller('platform/v1')
export class PlatformOpsController {
  private readonly logger = new Logger(PlatformOpsController.name);

  constructor(
    private readonly ops: PlatformOpsService,
    private readonly killSwitch: PlatformKillSwitchService,
    private readonly control: ControlPrismaService,
    // forwardRef: edge-peer.service imports the kill-switch services (an import cycle).
    @Optional()
    @Inject(forwardRef(() => EdgePeerService))
    private readonly edgePeers?: EdgePeerService,
    @Optional() private readonly epochs?: KillSwitchEpochService,
  ) {}

  @Get('kill-switch')
  @ApiOperation({ summary: 'Platform kill switch state' })
  @ApiResponse({ status: 200, type: KillSwitchStateDto })
  async state() {
    return view(await this.killSwitch.getState());
  }

  @Post('kill-switch/engage')
  @HttpCode(200)
  @ApiOperation({ summary: 'Engage: every agent of every tenant is denied' })
  @ApiResponse({ status: 200, type: KillSwitchStateDto })
  async engage(@Body() body: EngageDto, @Req() req: RequestWithPlatformCaller) {
    const b = parseBodyOrThrow(EngageSchema, body);
    const s = await this.killSwitch.activate(
      b.reason,
      `${caller(req)}: ${b.staff}`,
    );
    this.logger.warn(
      `platform kill switch ENGAGED by ${caller(req)} (staff ${b.staff})`,
    );
    this.auditInBackground(
      'ENGAGED',
      AUDIT_EVENT_TYPES.KILL_SWITCH_ACTIVATED,
      caller(req),
      {
        reason: b.reason,
        staff: b.staff,
        engagementId: s.activatedAt?.toISOString() ?? null,
      },
    );
    return view(s);
  }

  @Post('kill-switch/release')
  @HttpCode(200)
  @ApiOperation({
    summary:
      'Release one engagement; 409 engagement_changed if it is no longer the active one',
  })
  @ApiResponse({ status: 200, type: KillSwitchStateDto })
  @ApiResponse({ status: 409, description: 'engagement_changed' })
  async release(
    @Body() body: ReleaseDto,
    @Req() req: RequestWithPlatformCaller,
  ) {
    const b = parseBodyOrThrow(ReleaseSchema, body);
    const changed = await this.control.platformKillSwitch.updateMany({
      where: {
        id: SINGLETON,
        active: true,
        activatedAt: new Date(b.expectedEngagementId),
      },
      data: {
        active: false,
        deactivatedBy: `${caller(req)}: ${b.staff}`,
        deactivatedAt: new Date(),
      },
    });
    if (changed.count !== 1) {
      this.logger.warn(
        `platform kill switch release refused: engagement ${b.expectedEngagementId} is not the active one`,
      );
      throw new ConflictException({
        statusCode: 409,
        code: 'engagement_changed',
        message: 'engagement_changed',
      });
    }
    await this.epochs?.bumpPlatform();
    // docs/edge.md: restores the edge peers nothing else stops.
    await this.edgePeers?.allChanged();
    this.logger.warn(
      `platform kill switch RELEASED by ${caller(req)} (staff ${b.staff}, proposed by ${b.proposedBy ?? 'unknown'})`,
    );
    this.auditInBackground(
      'RELEASED',
      AUDIT_EVENT_TYPES.KILL_SWITCH_DEACTIVATED,
      caller(req),
      {
        staff: b.staff,
        proposedBy: b.proposedBy ?? null,
        engagementId: b.expectedEngagementId,
      },
    );
    return view(await this.killSwitch.getState());
  }

  /**
   * The switch row is committed before this runs, so the answer never waits on tenant chains (that
   * wait would grow with the tenant count). Failed tenants are logged by id in the service.
   */
  private auditInBackground(
    what: string,
    eventType: AuditEventType,
    by: string,
    data: Record<string, unknown>,
  ): void {
    void this.ops
      .auditPlatformSwitch(eventType, by, data)
      .then((r) =>
        this.logger.log(
          `platform kill switch ${what}: tenant audit chains ${r.audited} written, ${r.failed} failed`,
        ),
      )
      .catch(() =>
        this.logger.error(
          `platform kill switch ${what}: tenant audit chains not written`,
        ),
      );
  }

  @Get('tenants/:id/ops')
  @ApiOperation({
    summary:
      'Kill switches, quarantines, monthly decisions, agents and credential expiry',
  })
  @ApiResponse({ status: 200, type: TenantOpsDto })
  tenantOps(@Param('id', ParseUUIDPipe) id: string) {
    return this.ops.tenantOps(id);
  }

  @Post('tenants/:id/audit/verify')
  @HttpCode(200)
  @ApiOperation({ summary: "Full check of the tenant's audit hash chain" })
  @ApiResponse({ status: 200, type: AuditVerifyDto })
  async verify(
    @Param('id', ParseUUIDPipe) id: string,
    @Req() req: RequestWithPlatformCaller,
  ) {
    const r = await this.ops.verifyTenantAudit(id);
    this.logger.log(
      `platform: audit chain of tenant ${id} checked by ${caller(req)}: ${r.valid ? 'valid' : 'BROKEN'}`,
    );
    return r;
  }
}
