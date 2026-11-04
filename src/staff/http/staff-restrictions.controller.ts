import {
  Body,
  Controller,
  Get,
  HttpCode,
  NotFoundException,
  Param,
  ParseUUIDPipe,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import { z } from 'zod';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { ChangeRequestsService } from '../approvals/change-requests.service';
import { StaffAuthGuard } from '../auth/staff-auth.guard';
import {
  RequirePermission,
  StaffPermissionGuard,
} from '../auth/staff-permission.guard';
import { CurrentStaff, type StaffPrincipal } from '../auth/staff-principal';
import { StepUp } from '../auth/step-up';
import {
  RestrictionBody,
  RestrictionsService,
} from '../restrictions/restrictions.service';
import { parse } from './parse';

const Reason = z.object({ reason: z.string().trim().min(10).max(2000) });
const Note = z.object({ note: z.string().trim().max(2000).default('') });
const Resolve = z.object({
  resolution: z.enum(['confirmed', 'false_positive']),
});

/**
 * Restrictions, re-signup matches and the two-person queue (DESK spec §9, §11.3, §16). Which
 * restriction a caller may apply is decided per kind by RestrictionsService (OpenFGA permissions,
 * passkey for a ban); the route only requires that they may look at people.
 */
@Controller('staff/v1')
@UseGuards(StaffAuthGuard, StaffPermissionGuard)
export class StaffRestrictionsController {
  constructor(
    private readonly control: ControlPrismaService,
    private readonly restrictions: RestrictionsService,
    private readonly changes: ChangeRequestsService,
  ) {}

  @Post('restrictions')
  @RequirePermission('people.view')
  create(@CurrentStaff() s: StaffPrincipal, @Body() body: unknown) {
    return this.restrictions.create(s, parse(RestrictionBody, body));
  }

  @Get('restrictions')
  @RequirePermission('people.view')
  async list(@Query('status') status = 'active') {
    const now = new Date();
    const rows = await this.control.staffRestriction.findMany({
      where:
        status === 'active'
          ? {
              liftedAt: null,
              OR: [
                { kind: { in: ['BAN', 'WARNING'] } },
                { until: { gt: now } },
              ],
            }
          : {},
      orderBy: { startsAt: 'desc' },
      take: 200,
      include: { account: { select: { id: true, displayName: true } } },
    });
    const tenants = await this.control.tenant.findMany({
      where: {
        id: { in: rows.map((r) => r.tenantId).filter((x): x is string => !!x) },
      },
      select: { id: true, name: true },
    });
    return rows.map((r) => ({
      id: r.id,
      code: r.code,
      targetType: r.targetType,
      account: r.account,
      tenant: tenants.find((t) => t.id === r.tenantId) ?? null,
      kind: r.kind,
      category: r.category,
      startsAt: r.startsAt,
      until: r.until,
      createdBy: r.createdBy,
    }));
  }

  @Post('restrictions/:id/lift')
  @HttpCode(200)
  @RequirePermission('restrict.lift')
  async lift(
    @CurrentStaff() s: StaffPrincipal,
    @Param('id', ParseUUIDPipe) id: string,
    @Body() body: unknown,
  ) {
    await this.restrictions.lift(s, id, parse(Reason, body).reason);
    return { ok: true };
  }

  @Post('restrictions/:id/unban')
  @RequirePermission('restrict.unban.propose')
  unban(
    @CurrentStaff() s: StaffPrincipal,
    @Param('id', ParseUUIDPipe) id: string,
    @Body() body: unknown,
  ) {
    return this.restrictions.proposeUnban(s, id, parse(Reason, body).reason);
  }

  @Get('matches')
  @RequirePermission('matches.review')
  matches() {
    return this.control.staffRestrictionMatch.findMany({
      orderBy: { at: 'desc' },
      take: 200,
    });
  }

  @Post('matches/:id/resolve')
  @HttpCode(200)
  @RequirePermission('matches.review')
  async resolve(
    @CurrentStaff() s: StaffPrincipal,
    @Param('id', ParseUUIDPipe) id: string,
    @Body() body: unknown,
  ) {
    const { resolution } = parse(Resolve, body);
    const m = await this.control.staffRestrictionMatch.findUnique({
      where: { id },
    });
    if (!m || m.resolvedAt)
      throw new NotFoundException({
        code: 'not_found',
        message: 'No open match with this id.',
      });
    await this.control.staffRestrictionMatch.update({
      where: { id },
      data: { resolution, resolvedBy: s.staffId, resolvedAt: new Date() },
    });
    // A wrong block is undone by un-banning the ban it created (spec §9.5). A ban is never lifted
    // by one person (founder: un-ban needs a different Owner), so this opens the un-ban request.
    const unbans: string[] = [];
    if (resolution === 'false_positive' && m.newAccountId) {
      const system = await this.control.staffRestriction.findMany({
        where: {
          accountId: m.newAccountId,
          createdBy: 'system:resignup',
          liftedAt: null,
          kind: 'BAN',
        },
      });
      for (const r of system)
        unbans.push(
          (
            await this.restrictions.proposeUnban(
              s,
              r.id,
              'Re-signup match marked false positive',
            )
          ).id,
        );
    }
    return { ok: true, unbanRequests: unbans };
  }

  @Get('change-requests')
  @RequirePermission('people.view')
  changeRequests(
    @CurrentStaff() s: StaffPrincipal,
    @Query('box') box: 'waiting' | 'mine' | 'done' = 'waiting',
  ) {
    return this.changes.list(
      s,
      ['waiting', 'mine', 'done'].includes(box) ? box : 'waiting',
    );
  }

  @Post('change-requests/:id/approve')
  @HttpCode(200)
  @RequirePermission('people.view')
  @StepUp()
  approve(
    @CurrentStaff() s: StaffPrincipal,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    return this.changes.approve(s, id);
  }

  @Post('change-requests/:id/reject')
  @HttpCode(200)
  @RequirePermission('people.view')
  reject(
    @CurrentStaff() s: StaffPrincipal,
    @Param('id', ParseUUIDPipe) id: string,
    @Body() body: unknown,
  ) {
    return this.changes.reject(s, id, parse(Note, body).note);
  }

  @Post('change-requests/:id/cancel')
  @HttpCode(200)
  @RequirePermission('people.view')
  async cancel(
    @CurrentStaff() s: StaffPrincipal,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    await this.changes.cancel(s, id);
    return { ok: true };
  }
}
