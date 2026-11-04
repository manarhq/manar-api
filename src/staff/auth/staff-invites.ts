import { createHash, randomBytes } from 'node:crypto';
import {
  Body,
  Controller,
  ForbiddenException,
  HttpCode,
  Injectable,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { z } from 'zod';
import { throwFailClosed } from '../../common/fail-closed/fail-closed';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { StaffAuditService } from '../audit/staff-audit.service';
import { NoStaffAudit } from '../http/staff-audit.interceptor';
import { AllowUnboundStaff, StaffAuthGuard } from './staff-auth.guard';
import { StaffPermissionGuard } from './staff-permission.guard';
import type { RequestWithStaff } from './staff-principal';

export const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const hashInviteToken = (token: string) =>
  createHash('sha256').update(`manar-staff-invite:${token}`).digest('hex');

/** A new one-time token: the inviter hands it over out of band; only its hash is stored. */
export function newInviteToken(): {
  token: string;
  hash: string;
  expiresAt: Date;
} {
  const token = randomBytes(32).toString('base64url');
  return {
    token,
    hash: hashInviteToken(token),
    expiresAt: new Date(Date.now() + INVITE_TTL_MS),
  };
}

@Injectable()
export class StaffInvitesService {
  constructor(
    private readonly control: ControlPrismaService,
    private readonly audit: StaffAuditService,
  ) {}

  private async refuse(entraOid: string): Promise<never> {
    await this.audit.append({
      staffId: null,
      action: 'staff.invite_claim_refused',
      data: { entraOid },
    });
    throw new ForbiddenException({
      code: 'invite_invalid',
      message: 'This invite is not valid. Ask an Owner for a new one.',
    });
  }

  /**
   * Binds the INVITED row named by the token to this Entra identity: one conditional update (the
   * row must still be INVITED, unbound, unexpired and addressed to this email), so two concurrent
   * claims cannot both win and a used token never works again. The one-time token is the binding;
   * the email (unverified, from Fixio's own tenant) only narrows it to the invited address.
   */
  async claim(
    claims: { sub: string; email?: string; entra_oid: string; iss?: string },
    token: string,
  ): Promise<{ staffId: string }> {
    const hash = hashInviteToken(token);
    const email = (claims.email ?? '').trim().toLowerCase();
    if (!email) return this.refuse(claims.entra_oid);
    let bound: { count: number };
    try {
      bound = await this.control.staffMember.updateMany({
        where: {
          inviteTokenHash: hash,
          status: 'INVITED',
          entraOid: null,
          inviteExpiresAt: { gt: new Date() },
          email,
        },
        data: {
          entraOid: claims.entra_oid,
          subject: claims.sub,
          issuer: claims.iss ?? null,
          status: 'ACTIVE',
          boundAt: new Date(),
          inviteTokenHash: null,
          inviteExpiresAt: null,
        },
      });
    } catch (error) {
      // P2002: this Entra identity is already bound to another staff row.
      if ((error as { code?: string }).code === 'P2002') bound = { count: 0 };
      else throwFailClosed('control-db', error);
    }
    if (bound.count !== 1) return this.refuse(claims.entra_oid);
    const row = await this.control.staffMember.findUniqueOrThrow({
      where: { entraOid: claims.entra_oid },
    });
    await this.audit.append({
      staffId: row.id,
      action: 'staff.bound',
      targetType: 'STAFF',
      targetId: row.id,
      data: { by: 'invite' },
    });
    return { staffId: row.id };
  }
}

const ClaimBody = z.object({ token: z.string().min(20).max(200) });

@Controller('staff/v1/invites')
@UseGuards(StaffAuthGuard, StaffPermissionGuard)
export class StaffInvitesController {
  constructor(private readonly invites: StaffInvitesService) {}

  @Post('claim')
  @HttpCode(200)
  @AllowUnboundStaff()
  @NoStaffAudit()
  async claim(@Req() req: RequestWithStaff, @Body() body: unknown) {
    const parsed = ClaimBody.safeParse(body);
    if (!parsed.success || !req.unboundStaff)
      throw new ForbiddenException({
        code: 'invite_invalid',
        message: 'This invite is not valid.',
      });
    return this.invites.claim(req.unboundStaff, parsed.data.token);
  }
}
