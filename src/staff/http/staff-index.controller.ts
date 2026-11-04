import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Post,
  Put,
  Query,
  UseGuards,
} from '@nestjs/common';
import type { z } from 'zod';
import { throwFailClosed } from '../../common/fail-closed/fail-closed';
import { StaffAuthGuard } from '../auth/staff-auth.guard';
import {
  RequirePermission,
  StaffPermissionGuard,
} from '../auth/staff-permission.guard';
import { CurrentStaff, type StaffPrincipal } from '../auth/staff-principal';
import {
  OrgsQuery,
  PeopleQuery,
  StaffIndexService,
} from '../index/staff-index.service';
import {
  NoteBody,
  RevealBody,
  StaffRecordsService,
  TagsBody,
} from '../index/staff-records.service';
import { StaffRbacService } from '../rbac/staff-rbac.service';

function parse<T extends z.ZodType>(schema: T, body: unknown): z.infer<T> {
  const r = schema.safeParse(body ?? {});
  if (!r.success)
    throw new BadRequestException({
      code: 'invalid_request',
      message: 'Check the details and try again.',
      fields: r.error.issues.map((i) => i.path.join('.')),
    });
  return r.data;
}

/** Index, search and record pages (DESK spec §16). Every route is recorded by the interceptor. */
@Controller('staff/v1')
@UseGuards(StaffAuthGuard, StaffPermissionGuard)
export class StaffIndexController {
  constructor(
    private readonly index: StaffIndexService,
    private readonly records: StaffRecordsService,
    private readonly rbac: StaffRbacService,
  ) {}

  @Get('search')
  @RequirePermission('people.search')
  async search(@CurrentStaff() s: StaffPrincipal, @Query('q') q?: string) {
    let can: Set<string>;
    try {
      can = new Set(await this.rbac.permissionsOf(s.staffId));
    } catch (error) {
      throwFailClosed('openfga', error);
    }
    return this.index.search(String(q ?? ''), can as never);
  }

  @Post('people/query')
  @HttpCode(200)
  @RequirePermission('people.search')
  queryPeople(@Body() body: unknown) {
    return this.index.queryPeople(parse(PeopleQuery, body));
  }

  @Post('orgs/query')
  @HttpCode(200)
  @RequirePermission('orgs.search')
  queryOrgs(@Body() body: unknown) {
    return this.index.queryOrgs(parse(OrgsQuery, body));
  }

  @Get('people/:accountId')
  @RequirePermission('people.view')
  person(
    @CurrentStaff() s: StaffPrincipal,
    @Param('accountId', ParseUUIDPipe) id: string,
  ) {
    return this.records.person(s, id);
  }

  @Get('people/:accountId/security')
  @RequirePermission('people.view')
  security(
    @CurrentStaff() s: StaffPrincipal,
    @Param('accountId', ParseUUIDPipe) id: string,
  ) {
    return this.records.personSecurity(s, id);
  }

  @Get('people/:accountId/billing')
  @RequirePermission('people.view')
  billing(
    @CurrentStaff() s: StaffPrincipal,
    @Param('accountId', ParseUUIDPipe) id: string,
  ) {
    return this.records.personBilling(s, id);
  }

  @Post('people/:accountId/sessions/revoke')
  @HttpCode(200)
  @RequirePermission('people.sessions.revoke')
  revokeSessions(
    @CurrentStaff() s: StaffPrincipal,
    @Param('accountId', ParseUUIDPipe) id: string,
  ) {
    return this.records.revokeSessions(s, id);
  }

  @Get('orgs/:tenantId')
  @RequirePermission('orgs.view')
  org(
    @CurrentStaff() s: StaffPrincipal,
    @Param('tenantId', ParseUUIDPipe) id: string,
  ) {
    return this.records.org(s, id);
  }

  @Get('errors/:reference')
  @RequirePermission('errors.view')
  error(@Param('reference') reference: string) {
    return this.records.errorReference(reference.toUpperCase());
  }

  @Post('reveals')
  @RequirePermission('people.reveal_pii')
  reveal(@CurrentStaff() s: StaffPrincipal, @Body() body: unknown) {
    return this.records.reveal(s, parse(RevealBody, body));
  }

  @Post('notes')
  @RequirePermission('notes.write')
  addNote(@CurrentStaff() s: StaffPrincipal, @Body() body: unknown) {
    return this.records.addNote(s, parse(NoteBody, body));
  }

  @Delete('notes/:id')
  @RequirePermission('notes.write')
  deleteNote(
    @CurrentStaff() s: StaffPrincipal,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    return this.records.deleteNote(s, id);
  }

  @Put('tags')
  @RequirePermission('tags.write')
  setTags(@CurrentStaff() s: StaffPrincipal, @Body() body: unknown) {
    return this.records.setTags(s, parse(TagsBody, body));
  }
}
