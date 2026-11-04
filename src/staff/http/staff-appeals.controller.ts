import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import { z } from 'zod';
import { throwFailClosed } from '../../common/fail-closed/fail-closed';
import { AppealsService } from '../appeals/appeals.service';
import { StaffAuthGuard } from '../auth/staff-auth.guard';
import {
  RequirePermission,
  StaffPermissionGuard,
} from '../auth/staff-permission.guard';
import { CurrentStaff, type StaffPrincipal } from '../auth/staff-principal';
import { StaffRbacService } from '../rbac/staff-rbac.service';
import { RestrictionsService } from '../restrictions/restrictions.service';
import { parse } from './parse';

const Decide = z.object({
  outcome: z.enum(['UPHELD', 'OVERTURNED']),
  note: z.string().trim().min(10).max(2000),
});

/** Trust & Safety > Appeals (spec §9.4): a different staff member than the restriction's creator. */
@Controller('staff/v1/appeals')
@UseGuards(StaffAuthGuard, StaffPermissionGuard)
export class StaffAppealsController {
  constructor(
    private readonly appeals: AppealsService,
    private readonly restrictions: RestrictionsService,
    private readonly rbac: StaffRbacService,
  ) {}

  @Get()
  @RequirePermission('appeals.review')
  queue(@CurrentStaff() s: StaffPrincipal, @Query('status') status = 'OPEN') {
    return this.appeals.queue(
      s.staffId,
      (['OPEN', 'UPHELD', 'OVERTURNED'].includes(status)
        ? status
        : 'OPEN') as 'OPEN',
    );
  }

  @Post(':id/decide')
  @HttpCode(200)
  @RequirePermission('appeals.review')
  async decide(
    @CurrentStaff() s: StaffPrincipal,
    @Param('id', ParseUUIDPipe) id: string,
    @Body() body: unknown,
  ) {
    const d = parse(Decide, body);
    const a = await this.appeals.load(id);
    if (a.restriction.createdBy === s.staffId)
      throw new ForbiddenException({
        code: 'created_the_restriction',
        message:
          'Someone other than the person who restricted this account reviews the appeal.',
      });
    if (d.outcome === 'UPHELD') {
      await this.appeals.close(id, s.staffId, 'UPHELD', d.note);
      return { outcome: 'UPHELD' };
    }
    if (a.restriction.kind === 'SUSPEND') {
      let canLift: boolean;
      try {
        canLift = await this.rbac.can(s.staffId, 'restrict.lift');
      } catch (error) {
        throwFailClosed('openfga', error);
      }
      if (!canLift)
        throw new ForbiddenException({
          code: 'permission_required',
          message: 'An Admin overturns a suspension.',
        });
      await this.restrictions.lift(
        s,
        a.restriction.id,
        `Appeal ${a.code} overturned: ${d.note}`,
      );
      await this.appeals.close(id, s.staffId, 'OVERTURNED', d.note);
      return { outcome: 'OVERTURNED', lifted: true };
    }
    // A ban: the reviewer opens an un-ban request; a different Owner who did not ban approves it.
    const changeRequest = await this.restrictions.proposeUnban(
      s,
      a.restriction.id,
      `Appeal ${a.code} overturned: ${d.note}`,
      { fromAppeal: a.id },
    );
    await this.appeals.close(id, s.staffId, 'OVERTURNED', d.note);
    return { outcome: 'OVERTURNED', changeRequest };
  }
}
