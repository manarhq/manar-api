import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  ForbiddenException,
  Get,
  Header,
  HttpCode,
  NotFoundException,
  UnauthorizedException,
  Param,
  Post,
  Put,
  Query,
  StreamableFile,
  UseGuards,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  ApiBearerAuth,
  ApiExcludeEndpoint,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { z } from 'zod';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { CurrentAuth, type AuthContext } from '../auth/auth-context';
import { CurrentIdentity, IdentityGuard } from '../auth/identity.guard';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { canGrantRole } from '../auth/role-privilege';
import { RequireRole } from '../auth/require-role.decorator';
import { ROLES } from '../auth/roles';
import { RolesGuard } from '../auth/roles.guard';
import type { VerifiedIdentity } from '../auth/token-verifier.service';
import type { AppConfig } from '../config/env.validation';
import { ContactEmailService } from '../contact/contact-email.service';
import { ContactFlowService } from './contact-flow.service';
import { AccountService } from './account.service';
import { renderBadge } from './badge.svg';
import { DigestService } from './digest.service';
import { LaunchOfferService } from './launch-offer.service';
import { MembersService } from './members.service';
import { ProfileService } from './profile.service';
import { verifyToken } from './signed-token';

/** How recent the last interactive sign-in must be to delete an account. */
export const FRESH_SIGN_IN_SECONDS = 300;
const Toggle = z.object({ enabled: z.boolean() });
const AutoJoinBody = z.object({
  enabled: z.boolean(),
  seatCap: z.number().int().min(1).max(10_000).optional(),
});
const InviteBody = z.object({
  email: z.string().trim().email().max(254),
  role: z.enum(ROLES).default('DEVELOPER'),
});
const EmailBody = z.object({
  email: z.string().trim().email().max(254),
  locale: z.enum(['en', 'ar']).default('en'),
});
const CodeBody = z.object({ code: z.string().regex(/^\d{6}$/) });
const AcceptBody = z.object({ token: z.string().min(10).max(1024) });
const PrefsBody = z.object({
  weeklyDigest: z.boolean().optional(),
  timezone: z.string().max(64).optional(),
  locale: z.enum(['en', 'ar']).optional(),
});

/**
 * Unauthenticated by design; each route is rate limited per address and reads the control DB
 * only (the badge and counter are cached snapshots), so they cannot be used to load a workspace.
 */
@ApiTags('public')
@Controller('public')
export class GrowthPublicController {
  constructor(
    private readonly offer: LaunchOfferService,
    private readonly profiles: ProfileService,
    private readonly digest: DigestService,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  @Get('launch-offer')
  @Throttle({ human: { limit: 60, ttl: 60_000 } })
  @Header('Cache-Control', 'public, max-age=30, s-maxage=30')
  @ApiOperation({
    summary: 'Launch offer counter',
    description: 'How many of the free Pro slots are left. Numbers only.',
  })
  counter() {
    return this.offer.counter();
  }

  @Get('badge/:file')
  @Throttle({ human: { limit: 120, ttl: 60_000 } })
  @Header('Content-Type', 'image/svg+xml; charset=utf-8')
  @Header('Cache-Control', 'public, max-age=3600, s-maxage=3600')
  @Header('X-Content-Type-Options', 'nosniff')
  @Header(
    'Content-Security-Policy',
    "default-src 'none'; style-src 'unsafe-inline'",
  )
  @ApiOperation({ summary: '"Protected by Manar" badge (SVG)' })
  async badge(@Param('file') file: string, @Query('lang') lang?: string) {
    if (!file.endsWith('.svg')) throw new NotFoundException();
    const stats = await this.profiles.publicStats(file.slice(0, -4));
    return renderBadge(stats, lang === 'ar' ? 'ar' : 'en');
  }

  @Get('profile/:slug')
  @Throttle({ human: { limit: 60, ttl: 60_000 } })
  @Header('Cache-Control', 'public, max-age=300, s-maxage=300')
  @Header('X-Robots-Tag', 'noindex')
  @ApiOperation({
    summary: 'Public profile card',
    description:
      'Aggregate numbers only: devices, actions checked, blocked, secrets kept safe.',
  })
  profile(@Param('slug') slug: string) {
    return this.profiles.publicStats(slug);
  }

  /** One click, no sign-in. GET so a mail link works; POST for RFC 8058 one-click clients. */
  @Get('unsubscribe/:token')
  @Throttle({ human: { limit: 30, ttl: 60_000 } })
  @Header('Content-Type', 'text/html; charset=utf-8')
  @Header('Cache-Control', 'no-store')
  @ApiExcludeEndpoint()
  async unsubscribeGet(@Param('token') token: string) {
    await this.doUnsubscribe(token);
    return '<!doctype html><meta charset="utf-8"><title>Manar</title><body style="font-family:sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem"><p>You will not get the weekly email any more. / لن تصلك الرسالة الأسبوعية بعد الآن.</p></body>';
  }

  @Post('unsubscribe/:token')
  @HttpCode(200)
  @Throttle({ human: { limit: 30, ttl: 60_000 } })
  @ApiExcludeEndpoint()
  async unsubscribePost(@Param('token') token: string) {
    await this.doUnsubscribe(token);
    return { unsubscribed: true };
  }

  private async doUnsubscribe(token: string) {
    const secret = this.config.get('MANAR_LINK_SECRET', { infer: true });
    const id = secret ? verifyToken(secret, 'unsubscribe', token) : null;
    if (!id) throw new BadRequestException('invalid_link');
    await this.digest.unsubscribe(id);
  }
}

/** Needs a resolved workspace (owner or security admin). */
@ApiTags('workspace')
@ApiBearerAuth('jwt')
@Controller('workspace')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('TENANT_OWNER', 'SECURITY_ADMIN')
export class GrowthWorkspaceController {
  constructor(
    private readonly profiles: ProfileService,
    private readonly members: MembersService,
  ) {}

  @Get('badge')
  @ApiOperation({ summary: 'Public badge and profile card settings' })
  getBadge(@CurrentAuth() auth: AuthContext) {
    return this.profiles.get(auth.tenant.id);
  }

  @Put('badge')
  @ApiOperation({ summary: 'Turn the public badge and profile card on or off' })
  setBadge(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const { enabled } = parseBodyOrThrow(Toggle, body);
    return this.profiles.set(
      auth.tenant.id,
      enabled,
      auth.user.keycloakSubject,
    );
  }

  @Get('invites')
  @ApiOperation({ summary: 'Open invites' })
  async invites(@CurrentAuth() auth: AuthContext) {
    return { items: await this.members.listInvites(auth.tenant.id) };
  }

  @Post('invites')
  @ApiOperation({
    summary: 'Invite someone by email (signed link, expires, works once)',
  })
  invite(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const input = parseBodyOrThrow(InviteBody, body);
    if (!canGrantRole(auth.roles, input.role))
      throw new ForbiddenException('Cannot grant a role above your own');
    return this.members.createInvite(
      auth.tenant.id,
      auth.user.keycloakSubject,
      input.email,
      input.role,
    );
  }

  @Delete('invites/:id')
  @HttpCode(204)
  @ApiOperation({ summary: 'Revoke an invite' })
  async revoke(@CurrentAuth() auth: AuthContext, @Param('id') id: string) {
    await this.members.revokeInvite(
      auth.tenant.id,
      id,
      auth.user.keycloakSubject,
    );
  }

  @Get('auto-join')
  @ApiOperation({ summary: 'Microsoft auto-join setting' })
  getAutoJoin(@CurrentAuth() auth: AuthContext) {
    return this.members.autoJoinSetting(auth.tenant.id);
  }

  @Put('auto-join')
  @RequireRole('TENANT_OWNER') // owner only: it lets people into the workspace
  @ApiOperation({
    summary: 'Offer people from our Entra tenant a "Join" prompt at sign-in',
    description:
      'Matches the verified tenant id of the sign-in, never an email domain. The person still confirms. New members get the Developer role; joining stops at the seat cap.',
  })
  setAutoJoin(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const b = parseBodyOrThrow(AutoJoinBody, body);
    return this.members.setAutoJoin(
      auth.tenant.id,
      b.enabled,
      auth.user.keycloakSubject,
      b.seatCap,
    );
  }
}

/** Works before a workspace exists (token only), like `/workspaces/*`. */
@ApiTags('account')
@ApiBearerAuth('jwt')
@Controller()
@UseGuards(IdentityGuard)
export class GrowthIdentityController {
  constructor(
    private readonly members: MembersService,
    private readonly account: AccountService,
    private readonly contact: ContactFlowService,
    private readonly contactEmail: ContactEmailService,
  ) {}

  @Get('me/contact-email')
  @ApiOperation({
    summary: 'Your verified contact email (receipts, alerts, weekly email)',
  })
  contactStatus(@CurrentIdentity() id: VerifiedIdentity) {
    return this.contact.status(id);
  }

  @Post('me/contact-email')
  @HttpCode(200)
  @Throttle({ human: { limit: 10, ttl: 3_600_000 } })
  @ApiOperation({ summary: 'Send a 6-digit code to confirm a contact email' })
  contactRequest(
    @CurrentIdentity() id: VerifiedIdentity,
    @Body() body: unknown,
  ) {
    const b = parseBodyOrThrow(EmailBody, body);
    return this.contact.request(id, b.email, b.locale);
  }

  @Post('me/contact-email/confirm')
  @HttpCode(200)
  @Throttle({ human: { limit: 20, ttl: 3_600_000 } })
  @ApiOperation({ summary: 'Confirm the contact email with the code' })
  contactConfirm(
    @CurrentIdentity() id: VerifiedIdentity,
    @Body() body: unknown,
  ) {
    return this.contact.confirm(id, parseBodyOrThrow(CodeBody, body).code);
  }

  @Post('workspaces/invites/accept')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Accept an invite link (sign in as the invited address)',
  })
  accept(@CurrentIdentity() id: VerifiedIdentity, @Body() body: unknown) {
    return this.members.acceptInvite(
      id,
      parseBodyOrThrow(AcceptBody, body).token,
    );
  }

  @Get('workspaces/auto-join')
  @ApiOperation({
    summary:
      'The company workspace this sign-in may join (for a "Join?" prompt)',
  })
  autoJoinOffer(@CurrentIdentity() id: VerifiedIdentity) {
    return this.members.autoJoinOffer(id);
  }

  @Post('workspaces/auto-join')
  @HttpCode(200)
  @ApiOperation({ summary: 'Say yes to the join prompt' })
  autoJoin(@CurrentIdentity() id: VerifiedIdentity) {
    return this.members.autoJoin(id);
  }

  @Get('me/email-preferences')
  @ApiOperation({ summary: 'Weekly email, time zone and language' })
  prefs(@CurrentIdentity() id: VerifiedIdentity) {
    return this.members.getPrefs(id.issuer, id.subject);
  }

  @Put('me/email-preferences')
  @ApiOperation({ summary: 'Change the weekly email settings' })
  setPrefs(@CurrentIdentity() id: VerifiedIdentity, @Body() body: unknown) {
    return this.members.setPrefs(
      id.issuer,
      id.subject,
      parseBodyOrThrow(PrefsBody, body),
    );
  }

  @Get('account/export')
  @Throttle({ human: { limit: 5, ttl: 3_600_000 } })
  @Header('Content-Type', 'application/zip')
  @Header('Content-Disposition', 'attachment; filename="manar-export.zip"')
  @Header('Cache-Control', 'no-store')
  @ApiOperation({
    summary:
      'Download everything Manar holds about your workspaces (zip of JSON)',
  })
  async export(@CurrentIdentity() id: VerifiedIdentity) {
    return new StreamableFile(
      await this.account.exportZip(id.issuer, id.subject),
    );
  }

  @Get('account/deletion')
  @ApiOperation({ summary: 'Is account deletion scheduled?' })
  deletion(@CurrentIdentity() id: VerifiedIdentity) {
    return this.account.status(id.issuer, id.subject);
  }

  @Post('account/deletion')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Delete my account after a 7-day grace period',
    description:
      'Export first. Cancel with DELETE /account/deletion until the date returned.',
  })
  async requestDeletion(@CurrentIdentity() id: VerifiedIdentity) {
    // A destructive step needs a fresh sign-in (5 minutes). Unknown auth_time counts as stale.
    if (!id.authTime || Date.now() / 1000 - id.authTime > FRESH_SIGN_IN_SECONDS)
      throw new UnauthorizedException({
        statusCode: 401,
        code: 'reauth_required',
        maxAge: FRESH_SIGN_IN_SECONDS,
      });
    return this.account.request(
      id.issuer,
      id.subject,
      (await this.contactEmail.verified(id.issuer, id.subject)) ?? undefined,
    );
  }

  @Delete('account/deletion')
  @ApiOperation({ summary: 'Cancel a scheduled account deletion' })
  cancelDeletion(@CurrentIdentity() id: VerifiedIdentity) {
    return this.account.cancel(id.issuer, id.subject);
  }
}
