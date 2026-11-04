import type { BlockList } from 'node:net';
import {
  type CanActivate,
  type ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
  Optional,
  SetMetadata,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
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
import { clientIpOf, trustedPeers } from './client-ip';
import type { RequestWithStaff, StaffPrincipal } from './staff-principal';

export interface StaffTokenConfig {
  issuer: string;
  clientId: string;
  audience: string;
  entraTenantId: string;
}

export interface StaffClaims extends JWTPayload {
  sub: string;
  /** Display only: Entra's email claim is not a verified identity (Keycloak trustEmail is off). */
  email?: string;
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
 * manar-api-staff, brokered from Entra (`idp=entra`) in Fixio's tenant (`entra_tid`), with an Entra
 * object id. Local password users never pass. The binding is the immutable pair (oid, tid): the
 * guard then requires the staff row seeded with this oid. Email is display only and never checked
 * here (architect decision 4 Nov: the staff realm keeps trustEmail off, so `email_verified` is false
 * for brokered staff, and an email match must never stand in for the oid).
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
  if (typeof payload.entra_tid !== 'string' || !payload.entra_tid)
    throw refuse('no Entra tenant');
  if (payload.entra_tid !== cfg.entraTenantId) throw refuse('Entra tenant');
  if (typeof payload.entra_oid !== 'string' || !payload.entra_oid)
    throw refuse('no Entra oid');
  if (typeof payload.sub !== 'string' || !payload.sub)
    throw refuse('no subject');
  return payload as StaffClaims;
}

/** Lets the invite-claim route run for a verified staff token with no bound staff row yet. */
export const ALLOW_UNBOUND_KEY = 'staff:allow-unbound';
export const AllowUnboundStaff = () => SetMetadata(ALLOW_UNBOUND_KEY, true);

/**
 * Staff listener guard (spec §16): verifies the staff token, then requires an ACTIVE staff row
 * whose Entra object id is the token's `entra_oid`. Rows are bound only by a stable id: an
 * object id recorded at invite time, or a one-time invite token claimed out of band
 * (`POST /staff/v1/invites/claim`); an email claim alone never binds anything (security review,
 * 4 Nov). The staff member's address comes from DESK only when DESK is the TCP peer. Any database
 * failure is 503. Permissions and the passkey re-check: StaffPermissionGuard.
 */
@Injectable()
export class StaffAuthGuard implements CanActivate {
  private readonly desk: BlockList;

  constructor(
    private readonly config: ConfigService<AppConfig, true>,
    private readonly control: ControlPrismaService,
    private readonly audit: StaffAuditService,
    private readonly jwks: JwksCacheService,
    @Optional() private readonly reflector?: Reflector,
  ) {
    this.desk = trustedPeers(
      config.get?.('STAFF_TRUSTED_PROXY_CIDRS', { infer: true }),
    );
  }

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
    const { clientIp, peerIp } = clientIpOf(
      request.raw?.socket?.remoteAddress ?? request.ip,
      request.headers['x-manar-client-ip'],
      this.desk,
    );
    const allowUnbound = this.reflector?.getAllAndOverride<boolean>(
      ALLOW_UNBOUND_KEY,
      [ctx.getHandler(), ctx.getClass()],
    );
    const principal = await this.resolveStaff(claims, {
      allowUnbound: !!allowUnbound,
    });
    if (!principal) {
      request.unboundStaff = claims;
      return true;
    }
    request.staff = {
      ...principal,
      ip: clientIp,
      peerIp,
      requestId: String(request.id),
    };
    return true;
  }

  /** The ACTIVE staff member this token belongs to; null only for an allowed unbound caller. */
  async resolveStaff(
    claims: Pick<
      StaffClaims,
      'sub' | 'email' | 'entra_oid' | 'acr' | 'auth_time' | 'iss'
    >,
    opts: { allowUnbound?: boolean } = {},
  ): Promise<Omit<StaffPrincipal, 'requestId' | 'ip' | 'peerIp'> | null> {
    let row: StaffMember | null;
    try {
      row = await this.control.staffMember.findUnique({
        where: { entraOid: claims.entra_oid },
      });
      // A row pre-bound by object id learns its Keycloak subject at first sign-in, once.
      if (row && row.status === 'ACTIVE' && !row.subject) {
        const bound = await this.control.staffMember.updateMany({
          where: { id: row.id, subject: null },
          data: {
            subject: claims.sub,
            issuer: claims.iss ?? null,
            boundAt: new Date(),
          },
        });
        if (bound.count)
          await this.audit.append({
            staffId: row.id,
            action: 'staff.bound',
            targetType: 'STAFF',
            targetId: row.id,
            data: { by: 'entra_oid' },
          });
      }
      if (row && row.subject && row.subject !== claims.sub) {
        await this.audit.append({
          staffId: row.id,
          action: 'staff.identity_mismatch',
          targetType: 'STAFF',
          targetId: row.id,
          data: { reason: 'subject_changed' },
        });
        throw new ForbiddenException({
          code: 'staff_identity_mismatch',
          message:
            'This sign-in does not match your staff account. The Owners were told.',
        });
      }
    } catch (error) {
      if (error instanceof ForbiddenException) throw error;
      throwFailClosed('control-db', error);
    }
    if (!row && opts.allowUnbound) return null;
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
