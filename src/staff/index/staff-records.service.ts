import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { z } from 'zod';
import { StripeGateway } from '../../billing/stripe.gateway';
import { throwFailClosed } from '../../common/fail-closed/fail-closed';
import type { AppConfig } from '../../config/env.validation';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import { KeycloakAdminClient } from '../../keycloak/keycloak-admin.client';
import { StaffAuditService } from '../audit/staff-audit.service';
import type { StaffPrincipal } from '../auth/staff-principal';
import { personStatus } from '../restrictions/restriction-rules';
import { TrustLogService } from '../trust-log.service';
import { lastFour, maskEmail, maskIp } from './masking';

export const REVEAL_MS = 60 * 60 * 1000;
export const RevealBody = z.object({
  targetType: z.enum(['ACCOUNT', 'TENANT']),
  targetId: z.uuid(),
  reason: z.string().trim().min(10).max(500),
});
export const NoteBody = z.object({
  targetType: z.enum(['ACCOUNT', 'TENANT']),
  targetId: z.uuid(),
  body: z.string().trim().min(1).max(5000),
});
export const TagsBody = z.object({
  targetType: z.enum(['ACCOUNT', 'TENANT']),
  targetId: z.uuid(),
  tags: z
    .array(
      z
        .string()
        .trim()
        .toLowerCase()
        .regex(/^[a-z0-9][a-z0-9-]{0,39}$/),
    )
    .max(20),
});

/**
 * Person and org pages (DESK spec §8) and the record-level staff actions: reveal, notes, tags,
 * sign out everywhere. Everything is masked unless the caller holds a live reveal for that record
 * (founder 4 Nov). No route here returns session commands, tool calls, approval details, secrets,
 * prompts or file contents (spec §8.3): only control-DB rows, host inventory and Keycloak metadata.
 * Opening a record writes `staff.record_viewed` into the customer's own audit log (spec §11.5).
 */
@Injectable()
export class StaffRecordsService {
  private readonly logger = new Logger(StaffRecordsService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly keycloak: KeycloakAdminClient,
    private readonly stripe: StripeGateway,
    private readonly config: ConfigService<AppConfig, true>,
    private readonly trust: TrustLogService,
    private readonly staffAudit: StaffAuditService,
  ) {}

  async revealed(
    staffId: string,
    targetType: 'ACCOUNT' | 'TENANT',
    targetId: string,
  ): Promise<Date | null> {
    const r = await this.control.staffReveal.findFirst({
      where: { staffId, targetType, targetId, expiresAt: { gt: new Date() } },
      orderBy: { expiresAt: 'desc' },
    });
    return r?.expiresAt ?? null;
  }

  private async account(accountId: string) {
    const a = await this.control.account.findUnique({
      where: { id: accountId },
    });
    if (!a)
      throw new NotFoundException({
        code: 'not_found',
        message: 'No such person.',
      });
    return a;
  }

  /** Keycloak data exists only for the shared realm (AC-9); legacy realms answer "not available". */
  private realmOf(issuer: string): string | null {
    const shared = (this.config.get('AUTH_ISSUERS', { infer: true }) ?? '')
      .split(',')
      .map((s) => s.trim().replace(/\/+$/, ''))
      .filter(Boolean);
    if (!shared.includes(issuer.replace(/\/+$/, ''))) return null;
    return issuer.split('/realms/')[1]?.replace(/\/+$/, '') ?? null;
  }

  async person(s: StaffPrincipal, accountId: string) {
    const a = await this.account(accountId);
    const revealedUntil = await this.revealed(s.staffId, 'ACCOUNT', a.id);
    const [memberships, restrictions, appeals, notes, tags, deletion, contact] =
      await Promise.all([
        this.control.membership.findMany({
          where: { issuer: a.issuer, subject: a.subject },
          include: { tenant: { include: { entitlement: true } } },
          orderBy: { createdAt: 'asc' },
        }),
        this.control.staffRestriction.findMany({
          where: { accountId: a.id },
          orderBy: { startsAt: 'desc' },
        }),
        this.control.staffAppeal.findMany({
          where: { accountId: a.id },
          orderBy: { submittedAt: 'desc' },
        }),
        this.control.staffNote.findMany({
          where: { targetType: 'ACCOUNT', targetId: a.id, deletedAt: null },
          orderBy: { createdAt: 'desc' },
        }),
        this.control.staffTag.findMany({
          where: { targetType: 'ACCOUNT', targetId: a.id },
        }),
        this.control.accountDeletion.findUnique({
          where: { issuer_subject: { issuer: a.issuer, subject: a.subject } },
        }),
        this.control.contactEmail.findUnique({
          where: { issuer_subject: { issuer: a.issuer, subject: a.subject } },
        }),
      ]);
    const now = new Date();
    const devices = await this.devicesOf(
      memberships
        .filter((m) => m.status === 'ACTIVE')
        .map((m) => ({
          tenantId: m.tenantId,
          tenantName: m.tenant.name,
          kind: m.tenant.kind,
          status: m.tenant.status,
        })),
      a.subject,
    );
    const owned = memberships.filter(
      (m) => m.role === 'TENANT_OWNER' && m.status === 'ACTIVE',
    );
    const authorIds = [...new Set(notes.map((n) => n.authorId))];
    const authors = await this.control.staffMember.findMany({
      where: { id: { in: authorIds } },
      select: { id: true, displayName: true },
    });

    // The trust log first: if the customer's audit log cannot record this view, it is not shown.
    for (const tenantId of await this.trust.personalWorkspacesOf(a.id))
      await this.trust.recordView(s, tenantId, 'person');

    return {
      id: a.id,
      name: a.displayName,
      email: revealedUntil ? a.normalizedEmail : maskEmail(a.normalizedEmail),
      contactEmail: contact?.email
        ? revealedUntil
          ? contact.email
          : maskEmail(contact.email)
        : null,
      emailVerified: a.emailVerified,
      idp: a.idp,
      revealedUntil,
      status: personStatus(restrictions, now, {
        deletionPending: deletion?.status === 'SCHEDULED',
      }),
      deletion:
        deletion?.status === 'SCHEDULED'
          ? { executeAfter: deletion.executeAfter }
          : null,
      signedUpAt: a.createdAt,
      lastActiveAt: a.lastSeenAt,
      lastCountry: a.lastCountry,
      riskScore: a.riskScore,
      tags: tags.map((t) => t.tag),
      workspaces: memberships.map((m) => ({
        tenantId: m.tenantId,
        name: m.tenant.name,
        slug: m.tenant.slug,
        kind: m.tenant.kind,
        tenantStatus: m.tenant.status,
        roles: [m.role, ...m.extraRoles],
        membershipStatus: m.status,
        joinedAt: m.createdAt,
        plan: m.tenant.entitlement?.plan ?? 'free',
      })),
      devices,
      billing: owned.map((m) => ({
        tenantId: m.tenantId,
        name: m.tenant.name,
        plan: m.tenant.entitlement?.plan ?? 'free',
        status: m.tenant.entitlement?.status ?? 'active',
        trialEndsAt: m.tenant.entitlement?.trialEndsAt ?? null,
        interval: m.tenant.entitlement?.billingInterval ?? null,
        manual: m.tenant.entitlement?.manual ?? false,
        stripeCustomerId: revealedUntil
          ? (m.tenant.entitlement?.stripeCustomerId ?? null)
          : null,
        stripeSubscriptionId: revealedUntil
          ? (m.tenant.entitlement?.stripeSubscriptionId ?? null)
          : null,
      })),
      restrictions: restrictions.map((r) => ({
        id: r.id,
        code: r.code,
        kind: r.kind,
        category: r.category,
        internalNote: r.internalNote,
        startsAt: r.startsAt,
        until: r.until,
        createdBy: r.createdBy,
        liftedAt: r.liftedAt,
        inForce: personStatus([r], now) !== 'ACTIVE',
      })),
      appeals: appeals.map((x) => ({
        id: x.id,
        code: x.code,
        status: x.status,
        submittedAt: x.submittedAt,
        dueAt: x.dueAt,
      })),
      notes: notes.map((n) => ({
        id: n.id,
        body: n.body,
        authorId: n.authorId,
        author:
          authors.find((x) => x.id === n.authorId)?.displayName ??
          'Former staff',
        createdAt: n.createdAt,
      })),
      viewers: await this.viewersOf([
        a.id,
        ...(await this.trust.personalWorkspacesOf(a.id)),
      ]),
      timeline: this.timeline(a, memberships, restrictions, appeals),
    };
  }

  private async devicesOf(
    workspaces: {
      tenantId: string;
      tenantName: string;
      kind: string;
      status: string;
    }[],
    ownerSubject?: string,
  ) {
    const out: {
      tenantId: string;
      workspace: string;
      hostId: string;
      hostname: string;
      os: string;
      status: string;
      lastSeenAt: Date | null;
    }[] = [];
    for (const w of workspaces.slice(0, 20)) {
      if (w.status !== 'ACTIVE' && w.status !== 'SUSPENDED') continue;
      try {
        const db = await this.tenants.getClient(w.tenantId);
        const hosts = await db.host.findMany({
          where: ownerSubject ? { ownerSubject } : {},
          select: {
            id: true,
            hostname: true,
            os: true,
            status: true,
            lastSeenAt: true,
          },
          orderBy: { lastSeenAt: 'desc' },
          take: 50,
        });
        for (const h of hosts)
          out.push({
            tenantId: w.tenantId,
            workspace: w.tenantName,
            hostId: h.id,
            hostname: h.hostname,
            os: h.os,
            status: h.status,
            lastSeenAt: h.lastSeenAt,
          });
      } catch (error) {
        this.logger.warn(`devices of ${w.tenantId} not read: ${String(error)}`);
      }
    }
    return out;
  }

  /** "Staff who viewed this record" (spec §8.1 Trust tab), last 30 days, from the staff chain. */
  private async viewersOf(targetIds: string[]) {
    const rows = await this.control.staffAuditEvent.findMany({
      where: {
        targetId: { in: targetIds },
        staffId: { not: null },
        at: { gt: new Date(Date.now() - 30 * 86_400_000) },
        action: { in: ['trust.record_viewed', 'staff.revealed'] },
      },
      orderBy: { seq: 'desc' },
      take: 200,
      select: { staffId: true, at: true, action: true },
    });
    const staff = await this.control.staffMember.findMany({
      where: { id: { in: [...new Set(rows.map((r) => r.staffId!))] } },
      select: { id: true, displayName: true, team: true },
    });
    return rows.map((r) => ({
      staffId: r.staffId,
      name:
        staff.find((x) => x.id === r.staffId)?.displayName ?? 'Former staff',
      team: staff.find((x) => x.id === r.staffId)?.team ?? null,
      at: r.at,
      kind: r.action === 'staff.revealed' ? 'reveal' : 'view',
    }));
  }

  private timeline(
    a: { createdAt: Date; idp: string | null },
    memberships: {
      createdAt: Date;
      role: string;
      tenant: { name: string; kind: string };
    }[],
    restrictions: {
      startsAt: Date;
      kind: string;
      category: string;
      liftedAt: Date | null;
    }[],
    appeals: { submittedAt: Date; status: string }[],
  ) {
    const items = [
      { at: a.createdAt, kind: 'signup', text: a.idp ?? 'email' },
      ...memberships.map((m) => ({
        at: m.createdAt,
        kind:
          m.tenant.kind === 'PERSONAL'
            ? 'workspace_created'
            : 'workspace_joined',
        text: m.tenant.name,
        role: m.role,
      })),
      ...restrictions.flatMap((r) => [
        {
          at: r.startsAt,
          kind: `restriction_${r.kind.toLowerCase()}`,
          text: r.category,
        },
        ...(r.liftedAt
          ? [{ at: r.liftedAt, kind: 'restriction_lifted', text: r.category }]
          : []),
      ]),
      ...appeals.map((x) => ({
        at: x.submittedAt,
        kind: 'appeal',
        text: x.status,
      })),
    ];
    return items.sort((x, y) => y.at.getTime() - x.at.getTime()).slice(0, 50);
  }

  async personSecurity(s: StaffPrincipal, accountId: string) {
    const a = await this.account(accountId);
    const realm = this.realmOf(a.issuer);
    if (!realm) return { available: false as const, reason: 'legacy_realm' };
    const revealed = !!(await this.revealed(s.staffId, 'ACCOUNT', a.id));
    try {
      const [identities, credentials, sessions, failures] = await Promise.all([
        this.keycloak.federatedIdentities(realm, a.subject),
        this.keycloak.credentials(realm, a.subject),
        this.keycloak.userSessions(realm, a.subject),
        this.keycloak.loginErrors(realm, a.subject, 30).catch(() => []),
      ]);
      return {
        available: true as const,
        methods: [
          ...identities.map((i) => ({
            provider: i.identityProvider,
            idpUserId: revealed ? lastFour(i.userId) : null,
          })),
          ...(a.idp === 'email'
            ? [{ provider: 'email', idpUserId: null }]
            : []),
        ],
        credentials: credentials.map((c) => ({
          type: c.type,
          createdAt: c.createdDate ? new Date(c.createdDate) : null,
        })),
        sessions: sessions.map((x) => ({
          started: x.start ? new Date(x.start) : null,
          lastAccess: x.lastAccess ? new Date(x.lastAccess) : null,
          ip: revealed ? (x.ipAddress ?? null) : maskIp(x.ipAddress),
          clients: Object.values(x.clients ?? {}),
        })),
        failedSignIns: failures.map((f) => ({
          at: new Date(f.time),
          ip: revealed ? (f.ipAddress ?? null) : maskIp(f.ipAddress),
          error: f.error ?? null,
        })),
        signInHistory: {
          available: false as const,
          reason: 'not_collected_yet',
        },
      };
    } catch (error) {
      this.logger.warn(`Keycloak read failed for ${a.id}: ${String(error)}`);
      return {
        available: false as const,
        reason: 'identity_service_unavailable',
      };
    }
  }

  async personBilling(s: StaffPrincipal, accountId: string) {
    const a = await this.account(accountId);
    if (!this.stripe.configured)
      return { configured: false as const, workspaces: [] };
    const revealed = !!(await this.revealed(s.staffId, 'ACCOUNT', a.id));
    const owned = await this.control.membership.findMany({
      where: {
        issuer: a.issuer,
        subject: a.subject,
        role: 'TENANT_OWNER',
        status: 'ACTIVE',
      },
      include: { tenant: { include: { entitlement: true } } },
    });
    const stripe = this.stripe.client();
    const workspaces = [];
    for (const m of owned) {
      const customer = m.tenant.entitlement?.stripeCustomerId;
      if (!customer) continue;
      try {
        const [invoices, methods] = await Promise.all([
          stripe.invoices.list({ customer, limit: 12 }),
          stripe.paymentMethods.list({ customer, type: 'card', limit: 3 }),
        ]);
        workspaces.push({
          tenantId: m.tenantId,
          name: m.tenant.name,
          paymentMethods: methods.data.map((p) => ({
            brand: p.card?.brand ?? null,
            last4: revealed ? (p.card?.last4 ?? null) : null,
          })),
          invoices: invoices.data.map((i) => ({
            number: i.number,
            status: i.status,
            amountDue: i.amount_due,
            amountPaid: i.amount_paid,
            currency: i.currency,
            created: new Date(i.created * 1000),
            hostedUrl: i.hosted_invoice_url ?? null,
          })),
        });
      } catch (error) {
        this.logger.warn(
          `Stripe read failed for ${m.tenantId}: ${String(error)}`,
        );
        workspaces.push({
          tenantId: m.tenantId,
          name: m.tenant.name,
          unavailable: true,
        });
      }
    }
    return { configured: true as const, workspaces };
  }

  async revokeSessions(s: StaffPrincipal, accountId: string) {
    const a = await this.account(accountId);
    const realm = this.realmOf(a.issuer);
    if (!realm)
      throw new BadRequestException({
        code: 'legacy_realm',
        message: 'Sign-in for this account is managed by its company.',
      });
    for (const tenantId of await this.trust.personalWorkspacesOf(a.id))
      await this.trust.recordAction(s, tenantId, {
        action: 'sessions_revoked',
      });
    try {
      await this.keycloak.logoutUser(realm, a.subject);
    } catch (error) {
      throwFailClosed('keycloak', error);
    }
    await this.staffAudit.append({
      staffId: s.staffId,
      action: 'person.sessions_revoked',
      targetType: 'ACCOUNT',
      targetId: a.id,
      ip: s.ip,
      requestId: s.requestId,
    });
    return { ok: true };
  }

  async org(s: StaffPrincipal, tenantId: string) {
    const t = await this.control.tenant.findUnique({
      where: { id: tenantId },
      include: {
        entitlement: true,
        memberships: { orderBy: { createdAt: 'asc' } },
      },
    });
    if (!t || t.kind === 'SAMPLE')
      throw new NotFoundException({
        code: 'not_found',
        message: 'No such workspace.',
      });
    const revealedUntil = await this.revealed(s.staffId, 'TENANT', t.id);
    const [restrictions, notes, tags, accounts] = await Promise.all([
      this.control.staffRestriction.findMany({
        where: { tenantId: t.id, targetType: 'TENANT' },
        orderBy: { startsAt: 'desc' },
      }),
      this.control.staffNote.findMany({
        where: { targetType: 'TENANT', targetId: t.id, deletedAt: null },
        orderBy: { createdAt: 'desc' },
      }),
      this.control.staffTag.findMany({
        where: { targetType: 'TENANT', targetId: t.id },
      }),
      this.control.account.findMany({
        where: {
          OR: t.memberships.map((m) => ({
            issuer: m.issuer,
            subject: m.subject,
          })),
        },
        select: { id: true, issuer: true, subject: true },
      }),
    ]);
    const devices = await this.devicesOf([
      { tenantId: t.id, tenantName: t.name, kind: t.kind, status: t.status },
    ]);
    await this.trust.recordView(s, t.id, 'org');
    const now = new Date();
    return {
      id: t.id,
      name: t.name,
      slug: t.slug,
      kind: t.kind,
      tenantStatus: t.status,
      status: personStatus(restrictions, now),
      revealedUntil,
      createdAt: t.createdAt,
      entraLinked: !!t.entraTenantId,
      entraTenantId: revealedUntil
        ? t.entraTenantId
        : t.entraTenantId
          ? lastFour(t.entraTenantId)
          : null,
      plan: t.entitlement?.plan ?? 'free',
      billingStatus: t.entitlement?.status ?? 'active',
      trialEndsAt: t.entitlement?.trialEndsAt ?? null,
      stripeCustomerId: revealedUntil
        ? (t.entitlement?.stripeCustomerId ?? null)
        : null,
      members: t.memberships.map((m) => ({
        accountId:
          accounts.find((x) => x.issuer === m.issuer && x.subject === m.subject)
            ?.id ?? null,
        name: m.displayName ?? '',
        email: revealedUntil ? m.email : maskEmail(m.email),
        roles: [m.role, ...m.extraRoles],
        status: m.status,
        joinedAt: m.createdAt,
      })),
      devices,
      restrictions: restrictions.map((r) => ({
        id: r.id,
        code: r.code,
        kind: r.kind,
        category: r.category,
        internalNote: r.internalNote,
        startsAt: r.startsAt,
        until: r.until,
        liftedAt: r.liftedAt,
        createdBy: r.createdBy,
      })),
      notes: notes.map((n) => ({
        id: n.id,
        body: n.body,
        authorId: n.authorId,
        createdAt: n.createdAt,
      })),
      tags: tags.map((x) => x.tag),
      viewers: await this.viewersOf([t.id]),
    };
  }

  async reveal(s: StaffPrincipal, input: z.infer<typeof RevealBody>) {
    const tenantIds =
      input.targetType === 'ACCOUNT'
        ? (await this.account(input.targetId),
          await this.trust.personalWorkspacesOf(input.targetId))
        : [
            (
              await this.control.tenant.findUniqueOrThrow({
                where: { id: input.targetId },
              })
            ).id,
          ];
    const expiresAt = new Date(Date.now() + REVEAL_MS);
    // Logged first, to both chains (spec §12); a failed write reveals nothing.
    for (const tenantId of tenantIds)
      await this.trust.recordPii(s, tenantId, [
        'email',
        'identity_ids',
        'billing_ids',
      ]);
    await this.control.$transaction(async (tx) => {
      await tx.staffReveal.create({
        data: {
          staffId: s.staffId,
          targetType: input.targetType,
          targetId: input.targetId,
          reason: input.reason,
          expiresAt,
        },
      });
      await this.staffAudit.append(
        {
          staffId: s.staffId,
          action: 'staff.revealed',
          targetType: input.targetType,
          targetId: input.targetId,
          data: { reason: input.reason, expiresAt: expiresAt.toISOString() },
          ip: s.ip,
          requestId: s.requestId,
        },
        tx,
      );
    });
    return { expiresAt };
  }

  async addNote(s: StaffPrincipal, input: z.infer<typeof NoteBody>) {
    await this.assertTarget(input.targetType, input.targetId);
    return this.control.$transaction(async (tx) => {
      const note = await tx.staffNote.create({
        data: {
          targetType: input.targetType,
          targetId: input.targetId,
          body: input.body,
          authorId: s.staffId,
        },
      });
      await this.staffAudit.append(
        {
          staffId: s.staffId,
          action: 'note.added',
          targetType: input.targetType,
          targetId: input.targetId,
          data: { noteId: note.id },
          ip: s.ip,
          requestId: s.requestId,
        },
        tx,
      );
      return note;
    });
  }

  async deleteNote(s: StaffPrincipal, id: string) {
    const note = await this.control.staffNote.findUnique({ where: { id } });
    if (!note || note.deletedAt) throw new NotFoundException();
    if (note.authorId !== s.staffId)
      throw new ForbiddenException({
        code: 'not_author',
        message: 'Only the author can delete a note.',
      });
    await this.control.$transaction(async (tx) => {
      await tx.staffNote.update({
        where: { id },
        data: { deletedAt: new Date() },
      });
      await this.staffAudit.append(
        {
          staffId: s.staffId,
          action: 'note.deleted',
          targetType: note.targetType as 'ACCOUNT',
          targetId: note.targetId,
          data: { noteId: id },
          ip: s.ip,
          requestId: s.requestId,
        },
        tx,
      );
    });
    return { ok: true };
  }

  async setTags(s: StaffPrincipal, input: z.infer<typeof TagsBody>) {
    await this.assertTarget(input.targetType, input.targetId);
    const tags = [...new Set(input.tags)];
    await this.control.$transaction(async (tx) => {
      await tx.staffTag.deleteMany({
        where: {
          targetType: input.targetType,
          targetId: input.targetId,
          tag: { notIn: tags },
        },
      });
      for (const tag of tags)
        await tx.staffTag.upsert({
          where: {
            targetType_targetId_tag: {
              targetType: input.targetType,
              targetId: input.targetId,
              tag,
            },
          },
          create: {
            targetType: input.targetType,
            targetId: input.targetId,
            tag,
            addedBy: s.staffId,
          },
          update: {},
        });
      await this.staffAudit.append(
        {
          staffId: s.staffId,
          action: 'tags.set',
          targetType: input.targetType,
          targetId: input.targetId,
          data: { tags },
          ip: s.ip,
          requestId: s.requestId,
        },
        tx,
      );
    });
    return { tags };
  }

  private async assertTarget(type: 'ACCOUNT' | 'TENANT', id: string) {
    const found =
      type === 'ACCOUNT'
        ? await this.control.account.findUnique({
            where: { id },
            select: { id: true },
          })
        : await this.control.tenant.findUnique({
            where: { id },
            select: { id: true },
          });
    if (!found)
      throw new NotFoundException({
        code: 'not_found',
        message: 'No such record.',
      });
  }

  async errorReference(reference: string) {
    const r = await this.control.staffErrorReference.findUnique({
      where: { reference },
    });
    if (!r)
      throw new NotFoundException({
        code: 'not_found',
        message: 'No error with this reference in the last 30 days.',
      });
    const account =
      r.issuer && r.subject && r.issuer !== 'staff'
        ? await this.control.account.findUnique({
            where: { issuer_subject: { issuer: r.issuer, subject: r.subject } },
            select: { id: true, displayName: true },
          })
        : null;
    return {
      reference: r.reference,
      at: r.at,
      status: r.status,
      code: r.code,
      route: r.route,
      correlationId: r.correlationId,
      tenantId: r.tenantId,
      account,
      staffCaller: r.issuer === 'staff',
    };
  }
}
