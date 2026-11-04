import {
  type CanActivate,
  type ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  errors as joseErrors,
  jwtVerify,
  type JWTPayload,
  type JWTVerifyGetKey,
} from 'jose';
import {
  ACCEPTED_SIGNING_ALGORITHMS,
  extractBearerToken,
} from '../../auth/token-verifier.service';
import { JwksCacheService } from '../../auth/jwks-cache.service';
import { throwFailClosed } from '../../common/fail-closed/fail-closed';
import type { AppConfig } from '../../config/env.validation';
import { ControlPrismaService } from '../../database/control-prisma.service';
import type { StaffMember } from '../../generated/control-client/client';
import { StaffAuditService } from '../audit/staff-audit.service';
import type { RequestWithStaff, StaffPrincipal } from './staff-principal';

export interface StaffTokenConfig {
  issuer: string;
  clientId: string;
  audience: string;
  entraTenantId: string;
}

export interface StaffClaims extends JWTPayload {
  sub: string;
  email: string;
  name?: string;
  entra_oid: string;
  entra_tid: string;
  idp: string;
  acr?: string;
  auth_time?: number;
}

const refuse = (reason: string) => {
  // The reason goes to the log only; the caller learns nothing about which check failed.
  new Logger('StaffAuthGuard').warn(`staff token refused: ${reason}`);
  return new UnauthorizedException({
    code: 'staff_token_invalid',
    message: 'Sign in again to continue.',
  });
};

/**
 * DESK spec §16 guard 1 and AC-44: a vax-staff access token for client manar-admin, audience
 * manar-api-staff, brokered from Entra (`idp=entra`) in Fixio's tenant (`entra_tid`), with a
 * verified email and an Entra object id. Local password users never pass.
 */
export async function verifyStaffClaims(
  token: string,
  cfg: StaffTokenConfig,
  jwks: JWTVerifyGetKey,
): Promise<StaffClaims> {
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, jwks, {
      issuer: cfg.issuer,
      algorithms: [...ACCEPTED_SIGNING_ALGORITHMS],
    }));
  } catch (error) {
    if (error instanceof joseErrors.JOSEError) throw refuse(error.code);
    throw error;
  }
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (payload.typ !== 'Bearer') throw refuse('not an access token');
  if (payload.azp !== cfg.clientId) throw refuse('issued to another client');
  if (!aud.includes(cfg.audience)) throw refuse('audience');
  if (payload.idp !== 'entra') throw refuse('not brokered from Entra');
  if (payload.entra_tid !== cfg.entraTenantId) throw refuse('Entra tenant');
  if (typeof payload.entra_oid !== 'string' || !payload.entra_oid)
    throw refuse('no Entra oid');
  if (typeof payload.sub !== 'string' || !payload.sub)
    throw refuse('no subject');
  if (typeof payload.email !== 'string' || payload.email_verified !== true)
    throw refuse('no verified email');
  return payload as StaffClaims;
}

/**
 * Staff listener guard (spec §16): verifies the staff token, then requires an ACTIVE staff row
 * whose pinned Entra object id matches. The first sign-in of an INVITED row binds it by verified
 * email, once (AC-43); after that a different oid with the same email is refused and recorded.
 * Any database failure is 503. Permissions and the passkey re-check: StaffPermissionGuard.
 */
@Injectable()
export class StaffAuthGuard implements CanActivate {
  constructor(
    private readonly config: ConfigService<AppConfig, true>,
    private readonly control: ControlPrismaService,
    private readonly audit: StaffAuditService,
    private readonly jwks: JwksCacheService,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const request = ctx.switchToHttp().getRequest<RequestWithStaff>();
    const token = extractBearerToken(request.headers.authorization);
    if (!token) throw refuse('no bearer token');
    const issuer = this.config.get('STAFF_OIDC_ISSUER', { infer: true });
    const tid = this.config.get('STAFF_ENTRA_TENANT_ID', { infer: true });
    if (!issuer || !tid) throw refuse('staff API not configured');
    const claims = await verifyStaffClaims(
      token,
      {
        issuer,
        entraTenantId: tid,
        clientId: this.config.get('STAFF_OIDC_CLIENT_ID', { infer: true }),
        audience: this.config.get('STAFF_API_AUDIENCE', { infer: true }),
      },
      this.jwks.getJwks(issuer),
    );
    const principal = await this.resolveStaff(claims);
    const ipHeader = request.headers['x-manar-client-ip'];
    request.staff = {
      ...principal,
      ip: (Array.isArray(ipHeader) ? ipHeader[0] : ipHeader) ?? request.ip,
      requestId: String(request.id),
    };
    return true;
  }

  async resolveStaff(
    claims: Pick<
      StaffClaims,
      'sub' | 'email' | 'entra_oid' | 'acr' | 'auth_time' | 'iss'
    >,
  ): Promise<Omit<StaffPrincipal, 'requestId' | 'ip'>> {
    let row: StaffMember | null;
    try {
      row = await this.control.staffMember.findUnique({
        where: { entraOid: claims.entra_oid },
      });
      if (!row) {
        const byEmail = await this.control.staffMember.findUnique({
          where: { email: claims.email.trim().toLowerCase() },
        });
        if (byEmail?.entraOid && byEmail.entraOid !== claims.entra_oid) {
          await this.audit.append({
            staffId: byEmail.id,
            action: 'staff.identity_mismatch',
            targetType: 'STAFF',
            targetId: byEmail.id,
            data: { presentedOid: claims.entra_oid },
          });
          throw new ForbiddenException({
            code: 'staff_identity_mismatch',
            message:
              'This sign-in does not match your staff account. The Owners were told.',
          });
        }
        if (byEmail?.status === 'INVITED' && !byEmail.entraOid)
          row = await this.control.$transaction(async (tx) => {
            const bound = await tx.staffMember.update({
              where: { id: byEmail.id },
              data: {
                issuer: claims.iss ?? null,
                subject: claims.sub,
                entraOid: claims.entra_oid,
                status: 'ACTIVE',
                boundAt: new Date(),
              },
            });
            await this.audit.append(
              {
                staffId: bound.id,
                action: 'staff.bound',
                targetType: 'STAFF',
                targetId: bound.id,
              },
              tx,
            );
            return bound;
          });
      }
    } catch (error) {
      if (error instanceof ForbiddenException) throw error;
      throwFailClosed('control-db', error);
    }
    if (!row || row.status !== 'ACTIVE')
      throw new ForbiddenException({
        code: 'not_staff',
        message: 'You do not have access to Manar Desk.',
      });
    return {
      staffId: row.id,
      email: row.email,
      displayName: row.displayName,
      firstName: row.displayName.split(/\s+/)[0] ?? row.displayName,
      team: row.team,
      title: row.title,
      acr: claims.acr,
      authTime: claims.auth_time,
    };
  }
}
