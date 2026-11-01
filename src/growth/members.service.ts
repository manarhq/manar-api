import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  GoneException,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { splitRoles } from '../auth/membership.service';
import type { RoleName } from '../auth/roles';
import type { VerifiedIdentity } from '../auth/token-verifier.service';
import { EntitlementsService } from '../billing/entitlements.service';
import type { AppConfig } from '../config/env.validation';
import { ControlPrismaService } from '../database/control-prisma.service';
import {
  DEFAULT_MEMBER_ROLE,
  organisationTid,
} from '../workspaces/workspaces.service';
import { validZone } from './digest';
import { GrowthAuditService } from './growth-audit.service';
import { growthSetting } from './growth.config';
import { MailerService } from './mailer.service';
import { signToken, verifyToken } from './signed-token';

const DAY_MS = 86_400_000;
const MAX_OPEN_INVITES = 200;
/** Plans that are workspaces of people. Free and Pro are personal. */
const TEAM_PLANS = new Set(['company_trial', 'company', 'enterprise']);

/**
 * Company invites, the Microsoft auto-join and email preferences. Seats follow the existing
 * billable-user rule (a member is billed once they own a device or sign in that month; the daily
 * Company job sets the Stripe quantity), so adding a member needs no seat check of its own: what
 * is checked is that the workspace is a live team plan, not a lapsed one.
 */
@Injectable()
export class MembersService {
  constructor(
    private readonly control: ControlPrismaService,
    private readonly entitlements: EntitlementsService,
    private readonly mailer: MailerService,
    private readonly audit: GrowthAuditService,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  private secret(): string {
    const s = this.config.get('MANAR_LINK_SECRET', { infer: true });
    if (!s) throw new ServiceUnavailableException('links_not_configured');
    return s;
  }

  private async assertTeamWorkspace(tenantId: string) {
    const tenant = await this.control.tenant.findUnique({
      where: { id: tenantId },
    });
    if (!tenant || tenant.kind !== 'COMPANY' || tenant.status !== 'ACTIVE')
      throw new ForbiddenException('company_workspace_required');
    const e = await this.entitlements.get(tenantId);
    if (!TEAM_PLANS.has(e.plan))
      throw new ForbiddenException('team_plan_required');
    if (e.status === 'read_only')
      throw new ForbiddenException('workspace_read_only');
    return tenant;
  }

  // ---- invites ----

  async createInvite(
    tenantId: string,
    createdBy: string,
    email: string,
    role: RoleName,
  ) {
    const secret = this.secret();
    const tenant = await this.assertTeamWorkspace(tenantId);
    const address = email.trim().toLowerCase();
    const open = await this.control.workspaceInvite.count({
      where: {
        tenantId,
        usedAt: null,
        revokedAt: null,
        expiresAt: { gt: new Date() },
      },
    });
    if (open >= MAX_OPEN_INVITES)
      throw new ConflictException('too_many_open_invites');
    // A new invite to the same address replaces the old one.
    await this.control.workspaceInvite.updateMany({
      where: { tenantId, email: address, usedAt: null, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    const expiresAt = new Date(
      Date.now() + growthSetting(this.config, 'INVITE_TTL_DAYS') * DAY_MS,
    );
    const invite = await this.control.workspaceInvite.create({
      data: { tenantId, email: address, role, expiresAt, createdBy },
    });
    const web = (
      this.config.get('BILLING_CONSOLE_URL', { infer: true }) ?? ''
    ).replace(/\/+$/, '');
    const link = `${web}/join?invite=${signToken(secret, 'invite', invite.id, expiresAt)}`;
    const emailed = await this.mailer.send({
      to: address,
      subject: `You are invited to ${tenant.name} on Manar`,
      text: `You were invited to join ${tenant.name} on Manar.\nOpen this link while signed in with ${address}: ${link}\nIt works once and expires on ${expiresAt.toISOString().slice(0, 10)}.\n`,
      html: `<p>You were invited to join <b>${escapeHtml(tenant.name)}</b> on Manar.</p><p><a href="${escapeHtml(link)}">Accept the invite</a> (sign in with ${escapeHtml(address)}). It works once and expires on ${expiresAt.toISOString().slice(0, 10)}.</p>`,
    });
    await this.audit.record(
      tenantId,
      AUDIT_EVENT_TYPES.WORKSPACE_INVITE_CREATED,
      { type: 'human', id: createdBy },
      { inviteId: invite.id, role },
    );
    return { id: invite.id, email: address, role, expiresAt, emailed, link };
  }

  listInvites(tenantId: string) {
    return this.control.workspaceInvite.findMany({
      where: {
        tenantId,
        usedAt: null,
        revokedAt: null,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        email: true,
        role: true,
        expiresAt: true,
        createdAt: true,
      },
    });
  }

  async revokeInvite(tenantId: string, id: string, by: string) {
    const r = await this.control.workspaceInvite.updateMany({
      where: { id, tenantId, usedAt: null, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    if (r.count === 0) throw new NotFoundException('invite_not_found');
    await this.audit.record(
      tenantId,
      AUDIT_EVENT_TYPES.WORKSPACE_INVITE_REVOKED,
      { type: 'human', id: by },
      { inviteId: id },
    );
  }

  /** Accept with the signed token, while signed in as the invited address. Single use. */
  async acceptInvite(identity: VerifiedIdentity, token: string) {
    const id = verifyToken(this.secret(), 'invite', token);
    if (!id) throw new BadRequestException('invite_invalid');
    const invite = await this.control.workspaceInvite.findUnique({
      where: { id },
    });
    if (
      !invite ||
      invite.revokedAt ||
      invite.usedAt ||
      invite.expiresAt <= new Date()
    )
      throw new GoneException('invite_unavailable');
    // The link is a bearer token, so it is also bound to the invited address.
    if (!identity.email || identity.email.trim().toLowerCase() !== invite.email)
      throw new ForbiddenException('invite_email_mismatch');
    await this.assertTeamWorkspace(invite.tenantId);
    const used = await this.control.workspaceInvite.updateMany({
      where: {
        id,
        usedAt: null,
        revokedAt: null,
        expiresAt: { gt: new Date() },
      },
      data: { usedAt: new Date(), usedBy: identity.subject },
    });
    if (used.count !== 1) throw new GoneException('invite_unavailable');
    const split = splitRoles([invite.role as RoleName]);
    if (!split) throw new BadRequestException('invite_invalid');
    const key = {
      issuer_subject_tenantId: {
        issuer: identity.issuer,
        subject: identity.subject,
        tenantId: invite.tenantId,
      },
    };
    const existing = await this.control.membership.findUnique({ where: key });
    if (existing?.status !== 'ACTIVE') {
      const data = {
        status: 'ACTIVE' as const,
        role: split.role,
        extraRoles: split.extraRoles,
        grantedBy: `invite:${invite.createdBy}`,
        email: identity.email,
        displayName: identity.displayName,
      };
      if (existing) await this.control.membership.update({ where: key, data });
      else
        await this.control.membership.create({
          data: {
            issuer: identity.issuer,
            subject: identity.subject,
            tenantId: invite.tenantId,
            ...data,
          },
        });
    }
    await this.audit.record(
      invite.tenantId,
      AUDIT_EVENT_TYPES.WORKSPACE_INVITE_ACCEPTED,
      { type: 'human', id: identity.subject },
      { inviteId: id },
    );
    return { tenantId: invite.tenantId };
  }

  // ---- Microsoft auto-join ----

  async autoJoinSetting(tenantId: string) {
    const t = await this.control.tenant.findUnique({ where: { id: tenantId } });
    return {
      available: t?.kind === 'COMPANY' && !!t.entraTenantId,
      enabled: !!t?.autoJoinEntra,
    };
  }

  async setAutoJoin(tenantId: string, enabled: boolean, by: string) {
    const t = await this.control.tenant.findUnique({ where: { id: tenantId } });
    if (t?.kind !== 'COMPANY' || !t.entraTenantId)
      throw new ForbiddenException('entra_company_required');
    await this.control.tenant.update({
      where: { id: tenantId },
      data: { autoJoinEntra: enabled },
    });
    await this.audit.record(
      tenantId,
      AUDIT_EVENT_TYPES.WORKSPACE_AUTOJOIN_CHANGED,
      { type: 'human', id: by },
      { enabled },
    );
    return { available: true, enabled };
  }

  /**
   * Called after sign-in. Joins the caller to the COMPANY workspace of their Entra tenant when the
   * admin turned auto-join on. The match is the verified `tid` of THIS Microsoft sign-in
   * (`organisationTid`), never an email domain; a consumer account, GitHub or an email link carry
   * no tid and never match. Someone an admin removed is not re-added.
   */
  async autoJoin(
    identity: VerifiedIdentity,
  ): Promise<{ tenantId: string | null }> {
    const tid = organisationTid(identity);
    if (!tid) return { tenantId: null };
    const tenant = await this.control.tenant.findFirst({
      where: {
        kind: 'COMPANY',
        entraTenantId: tid,
        autoJoinEntra: true,
        status: 'ACTIVE',
      },
    });
    if (!tenant) return { tenantId: null };
    const e = await this.entitlements.get(tenant.id);
    if (!TEAM_PLANS.has(e.plan) || e.status === 'read_only')
      return { tenantId: null };
    const key = {
      issuer_subject_tenantId: {
        issuer: identity.issuer,
        subject: identity.subject,
        tenantId: tenant.id,
      },
    };
    const existing = await this.control.membership.findUnique({ where: key });
    if (existing?.status === 'ACTIVE') return { tenantId: tenant.id };
    if (existing?.status === 'REMOVED') return { tenantId: null };
    const split = splitRoles([DEFAULT_MEMBER_ROLE])!;
    const data = {
      status: 'ACTIVE' as const,
      role: split.role,
      extraRoles: split.extraRoles,
      grantedBy: 'auto-join:entra',
      email: identity.email,
      displayName: identity.displayName,
    };
    if (existing) await this.control.membership.update({ where: key, data });
    else
      await this.control.membership.create({
        data: {
          issuer: identity.issuer,
          subject: identity.subject,
          tenantId: tenant.id,
          ...data,
        },
      });
    await this.audit.record(
      tenant.id,
      AUDIT_EVENT_TYPES.WORKSPACE_MEMBER_AUTOJOINED,
      { type: 'human', id: identity.subject },
      {},
    );
    return { tenantId: tenant.id };
  }

  // ---- email preferences (the caller's personal membership) ----

  async getPrefs(issuer: string, subject: string) {
    const m = await this.control.membership.findFirst({
      where: {
        issuer,
        subject,
        status: 'ACTIVE',
        tenant: { kind: 'PERSONAL' },
      },
    });
    return {
      weeklyDigest: m?.weeklyDigest ?? true,
      timezone: validZone(m?.timezone),
      locale: m?.locale === 'ar' ? 'ar' : 'en',
    };
  }

  async setPrefs(
    issuer: string,
    subject: string,
    p: { weeklyDigest?: boolean; timezone?: string; locale?: 'en' | 'ar' },
  ) {
    const tz = p.timezone === undefined ? undefined : validZone(p.timezone);
    await this.control.membership.updateMany({
      where: { issuer, subject, status: 'ACTIVE' },
      data: {
        ...(p.weeklyDigest === undefined
          ? {}
          : { weeklyDigest: p.weeklyDigest }),
        ...(tz === undefined ? {} : { timezone: tz }),
        ...(p.locale === undefined ? {} : { locale: p.locale }),
      },
    });
    return this.getPrefs(issuer, subject);
  }
}

const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
