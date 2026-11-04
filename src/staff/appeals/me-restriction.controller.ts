import { Body, Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  AllowRestricted,
  CurrentIdentity,
  IdentityGuard,
} from '../../auth/identity.guard';
import type { VerifiedIdentity } from '../../auth/token-verifier.service';
import { parse } from '../http/parse';
import { AppealsService, MAX_APPEAL } from './appeals.service';

const AppealBody = z.object({
  text: z.string().max(MAX_APPEAL),
  turnstileToken: z.string().min(1).max(2048),
});

/**
 * The two routes a suspended or banned person can still call (DESK spec §9.2, §9.4): what the
 * restriction is, and an appeal. Human listener, token only, restricted callers allowed.
 */
@ApiTags('account')
@Controller('me')
@UseGuards(IdentityGuard)
@AllowRestricted()
export class MeRestrictionController {
  constructor(private readonly appeals: AppealsService) {}

  @Get('restriction')
  @ApiOperation({
    summary:
      'Whether Manar restricted this account: kind, reason category, end time, appeal',
  })
  restriction(@CurrentIdentity() id: VerifiedIdentity) {
    return this.appeals.restrictionOf(id.issuer, id.subject);
  }

  @Post('appeals')
  @ApiOperation({
    summary: 'Appeal a restriction (Turnstile; once every 24 hours)',
  })
  appeal(
    @CurrentIdentity() id: VerifiedIdentity,
    @Body() body: unknown,
    @Req() req: FastifyRequest,
  ) {
    const b = parse(AppealBody, body);
    return this.appeals.submit(id.issuer, id.subject, {
      text: b.text,
      turnstileToken: b.turnstileToken,
      ip: req.ip,
    });
  }
}
