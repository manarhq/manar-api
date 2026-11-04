import { createParamDecorator, type ExecutionContext } from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import type { StaffTeam } from '../../generated/control-client/client';

/** Who is calling the staff API, from a verified staff token and an ACTIVE staff row. */
export interface StaffPrincipal {
  staffId: string;
  email: string;
  displayName: string;
  firstName: string;
  team: StaffTeam;
  title: string;
  /** `acr` and `auth_time` of the token, for the passkey step-up. */
  acr?: string;
  authTime?: number;
  /** The staff member's address: DESK's forwarded value when DESK is the peer, else the peer. */
  ip?: string;
  /** The TCP peer that called the staff listener. */
  peerIp?: string;
  requestId: string;
}

export type RequestWithStaff = FastifyRequest & {
  staff?: StaffPrincipal;
  /** A verified staff token with no bound row (only on @AllowUnboundStaff routes). */
  unboundStaff?: {
    sub: string;
    /** Display only, unverified. */
    email?: string;
    entra_oid: string;
    iss?: string;
  };
};

export const TEAM_LABEL: Record<StaffTeam, string> = {
  DEV: 'Dev',
  SALES: 'Sales',
  PARTNERSHIPS: 'Partnerships',
  SUPPORT: 'Support',
  BILLING: 'Billing',
  TRUST_SAFETY: 'Trust & Safety',
  LEADERSHIP: 'Leadership',
};

/** The badge the customer sees in their audit log: "Ali · Manar Sales" (spec §13). */
export function badge(p: Pick<StaffPrincipal, 'firstName' | 'team'>): string {
  return `${p.firstName} · Manar ${TEAM_LABEL[p.team]}`;
}

export const CurrentStaff = createParamDecorator(
  (_d: unknown, ctx: ExecutionContext): StaffPrincipal => {
    const staff = ctx.switchToHttp().getRequest<RequestWithStaff>().staff;
    if (!staff)
      throw new Error('@CurrentStaff() on a route without StaffAuthGuard');
    return staff;
  },
);
