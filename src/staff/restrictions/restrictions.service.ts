import { randomInt } from 'node:crypto';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
  type OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { z } from 'zod';
import { StripeGateway } from '../../billing/stripe.gateway';
import { throwFailClosed } from '../../common/fail-closed/fail-closed';
import type { AppConfig } from '../../config/env.validation';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import type {
  Prisma,
  StaffChangeRequest,
  StaffRestriction,
} from '../../generated/control-client/client';
import { KeycloakAdminClient } from '../../keycloak/keycloak-admin.client';
import { PlatformSuspension } from '../../platform/platform-suspension';
import { ChangeRequestsService } from '../approvals/change-requests.service';
import { StaffAuditService } from '../audit/staff-audit.service';
import type { StaffPrincipal } from '../auth/staff-principal';
import { checkStepUp } from '../auth/step-up';
import { StaffRbacService } from '../rbac/staff-rbac.service';
import { TrustLogService } from '../trust-log.service';
import { fingerprint, normalizeEmail } from './fingerprints';
import {
  CATEGORIES,
  DURATIONS,
  isInForce,
  planRestriction,
  type Category,
} from './restriction-rules';

export const RestrictionBody = z.object({
  target: z.object({ type: z.enum(['ACCOUNT', 'TENANT']), id: z.uuid() }),
  kind: z.enum(['WARNING', 'SUSPEND', 'BAN']),
  category: z.enum(CATEGORIES),
  note: z.string().trim().min(20).max(5000),
  duration: z
    .enum(Object.keys(DURATIONS) as [keyof typeof DURATIONS])
    .optional(),
  immediate: z.boolean().optional(),
  /** Founder 4 Nov: for each company the person is the only Owner of, when no Admin can take over. */
  ownerPlan: z.record(z.uuid(), z.enum(['transfer', 'ban_org'])).optional(),
});
export type RestrictionInput = z.infer<typeof RestrictionBody>;

const PAYING_PLANS = ['pro', 'company', 'enterprise'] as const;
const HANDOVER_NOTICE_MS = 7 * 86_400_000;
const yymm = () => new Date().toISOString().slice(2, 7).replace('-', '');

interface CancelledSubscription {
  tenantId: string;
  subscriptionId: string;
  customerId: string | null;
  currency: string | null;
  amount: number | null;
  periodStart: number | null;
  periodEnd: number | null;
  error?: string;
}

/**
 * Warn, suspend, ban, lift and un-ban, for people and orgs (DESK spec §9). The decision is
 * `planRestriction` (pure); this applies it: the restriction row and its keyed fingerprints, the
 * customer's trust log, Keycloak sessions, Stripe (founder 4 Nov: a paying ban cancels at once,
 * no refund; an overturned ban gives a pro-rata credit), the owner handover, and org suspension
 * through PlatformSuspension. Enforcement itself is the restriction row: every customer token and
 * every device of a restricted owner is refused from the moment it commits.
 */
@Injectable()
export class RestrictionsService implements OnModuleInit {
  private readonly logger = new Logger(RestrictionsService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly config: ConfigService<AppConfig, true>,
    private readonly rbac: StaffRbacService,
    private readonly changes: ChangeRequestsService,
    private readonly trust: TrustLogService,
    private readonly audit: StaffAuditService,
    private readonly keycloak: KeycloakAdminClient,
    private readonly stripe: StripeGateway,
    private readonly platform: PlatformSuspension,
  ) {}

  onModuleInit() {
    const permsFor = (p: Record<string, unknown>) =>
      p.kind === 'BAN'
        ? ['restrict.ban' as const]
        : ['restrict.suspend' as const];
    this.changes.register('suspend_proposal', {
      approvePermissions: () => ['restrict.suspend'],
      execute: (cr, decider) => this.executeProposal(cr, decider),
    });
    this.changes.register('immediate_restriction', {
      approvePermissions: (p) => ['restrict.immediate.approve', ...permsFor(p)],
      execute: (cr, decider) => this.executeProposal(cr, decider),
    });
    this.changes.register('unban', {
      approvePermissions: () => ['restrict.unban.approve'],
      refuseDecider: async (cr, decider) => {
        const r = await this.control.staffRestriction.findUnique({
          where: { id: cr.targetId },
        });
        return r?.createdBy === decider.staffId ? 'issued_the_ban' : null;
      },
      execute: (cr, decider) => this.executeUnban(cr, decider),
    });
  }

  private fpKey(): string {
    const key = this.config.get('RESTRICTION_FINGERPRINT_KEY', { infer: true });
    if (!key) throw new Error('RESTRICTION_FINGERPRINT_KEY is not set');
    return key;
  }

  /** Spec §9.3: paying = owns a pro, company or enterprise workspace, active or past_due, not manual. */
  private async target(type: 'ACCOUNT' | 'TENANT', id: string) {
    const now = new Date();
    if (type === 'ACCOUNT') {
      const account = await this.control.account.findUnique({
        where: { id },
        include: { restrictions: true },
      });
      if (!account)
        throw new NotFoundException({
          code: 'not_found',
          message: 'No such person.',
        });
      const owned = await this.control.membership.findMany({
        where: {
          issuer: account.issuer,
          subject: account.subject,
          role: 'TENANT_OWNER',
          status: 'ACTIVE',
        },
        include: { tenant: { include: { entitlement: true } } },
      });
      return { account, tenant: null, rows: account.restrictions, owned, now };
    }
    const tenant = await this.control.tenant.findUnique({
      where: { id },
      include: { entitlement: true },
    });
    if (!tenant || tenant.kind !== 'COMPANY')
      throw new NotFoundException({
        code: 'not_found',
        message: 'No such company workspace.',
      });
    const rows = await this.control.staffRestriction.findMany({
      where: { targetType: 'TENANT', tenantId: id },
    });
    return { account: null, tenant, rows, owned: [], now };
  }

  private paying(
    e: { plan: string; status: string; manual: boolean } | null | undefined,
  ) {
    return (
      !!e &&
      (PAYING_PLANS as readonly string[]).includes(e.plan) &&
      ['active', 'past_due'].includes(e.status) &&
      !e.manual
    );
  }

  async create(s: StaffPrincipal, input: RestrictionInput) {
    const t = await this.target(input.target.type, input.target.id);
    const live = t.rows.filter((r) => isInForce(r, t.now));
    const current = live.some((r) => r.kind === 'BAN')
      ? 'BAN'
      : live.some((r) => r.kind === 'SUSPEND')
        ? 'SUSPEND'
        : null;
    const warnedAt =
      live
        .filter((r) => r.kind === 'WARNING')
        .map((r) => r.startsAt)
        .sort((a, b) => b.getTime() - a.getTime())[0] ?? null;
    const paying = t.account
      ? t.owned.some((m) => this.paying(m.tenant.entitlement))
      : this.paying(t.tenant.entitlement);
    let permissions: Set<string>;
    try {
      permissions = new Set(await this.rbac.permissionsOf(s.staffId));
    } catch (error) {
      throwFailClosed('openfga', error);
    }
    const plan = planRestriction({
      kind: input.kind,
      duration: input.duration,
      category: input.category,
      note: input.note,
      immediate: input.immediate,
      caller: { permissions: permissions as never },
      target: { paying, warnedAt, current },
      now: t.now,
    });
    if ('refused' in plan) {
      const status =
        plan.refused === 'permission_required'
          ? ForbiddenException
          : plan.refused === 'warning_required' ||
              plan.refused === 'already_banned'
            ? ConflictException
            : BadRequestException;
      throw new status({
        code: plan.refused,
        message:
          refusalText[plan.refused] ?? 'This restriction cannot be applied.',
      });
    }
    if (input.kind === 'BAN') checkStepUp(s); // spec §9.1: ban needs the passkey re-check
    if (t.account && input.kind !== 'WARNING')
      await this.checkOwnerPlan(t.owned, t.account, input.ownerPlan);
    if (plan.action === 'propose') {
      const changeRequest = await this.changes.propose(s, {
        kind: plan.changeKind,
        targetId: input.target.id,
        payload: { ...input },
        reason: input.note,
      });
      return { changeRequest };
    }
    const restriction = await this.apply(s, input, plan.until ?? null, null);
    return { restriction };
  }

  /** A sole company Owner: an Admin takes over after 7 days, else staff must choose (founder 4 Nov). */
  private async checkOwnerPlan(
    owned: { tenantId: string; tenant: { kind: string } }[],
    account: { issuer: string; subject: string },
    ownerPlan: RestrictionInput['ownerPlan'],
  ) {
    const needChoice: string[] = [];
    for (const m of owned.filter((x) => x.tenant.kind === 'COMPANY')) {
      const { soleOwner, candidate } = await this.successionOf(
        m.tenantId,
        account,
      );
      if (soleOwner && !candidate && !ownerPlan?.[m.tenantId])
        needChoice.push(m.tenantId);
    }
    if (needChoice.length)
      throw new ConflictException({
        code: 'owner_plan_required',
        tenants: needChoice,
        message:
          'This person is the only Owner of a company with no Admin to take over. Choose a transfer through support or banning the whole org.',
      });
  }

  private async successionOf(
    tenantId: string,
    account: { issuer: string; subject: string },
  ) {
    const members = await this.control.membership.findMany({
      where: { tenantId, status: 'ACTIVE' },
      orderBy: { createdAt: 'asc' },
    });
    const isMe = (m: { issuer: string; subject: string }) =>
      m.issuer === account.issuer && m.subject === account.subject;
    const owners = members.filter(
      (m) => m.role === 'TENANT_OWNER' || m.extraRoles.includes('TENANT_OWNER'),
    );
    const soleOwner = owners.length === 1 && isMe(owners[0]!);
    const candidate =
      members.find(
        (m) =>
          !isMe(m) &&
          (m.role === 'SECURITY_ADMIN' ||
            m.extraRoles.includes('SECURITY_ADMIN')),
      ) ?? null;
    return { soleOwner, candidate };
  }

  private async executeProposal(
    cr: StaffChangeRequest,
    decider: StaffPrincipal,
  ) {
    const input = RestrictionBody.parse(cr.payload);
    const until =
      input.kind === 'SUSPEND' && input.duration
        ? new Date(Date.now() + DURATIONS[input.duration])
        : null;
    const proposer = { staffId: cr.proposedBy };
    const r = await this.apply(decider, input, until, cr.id, proposer.staffId);
    return { restrictionId: r.id, code: r.code };
  }

  /**
   * Commits the restriction (enforcement starts here) after the customer's trust log has the event,
   * then runs the effects. A failed effect is recorded on the restriction and does not undo it.
   */
  async apply(
    s: StaffPrincipal,
    input: RestrictionInput,
    until: Date | null,
    changeRequestId: string | null,
    createdBy = s.staffId,
  ): Promise<StaffRestriction> {
    const t = await this.target(input.target.type, input.target.id);
    const change =
      input.kind === 'WARNING'
        ? 'warned'
        : input.kind === 'SUSPEND'
          ? 'suspended'
          : 'banned';
    // 1. The customer's own audit log first: no silent staff action (spec §11.5).
    if (t.account) {
      for (const tenantId of await this.trust.personalWorkspacesOf(
        t.account.id,
      ))
        await this.trust.recordRestriction(s, tenantId, {
          change,
          category: input.category,
          scope: 'self',
          until,
        });
    } else
      await this.trust.recordRestriction(s, t.tenant.id, {
        change,
        category: input.category,
        scope: 'workspace',
        until,
      });

    // 2. The restriction and its fingerprints, in one transaction with the staff audit row.
    const fps = input.kind === 'WARNING' ? [] : await this.fingerprintsOf(t);
    const restriction = await this.control.$transaction(async (tx) => {
      const row = await tx.staffRestriction.create({
        data: {
          code: `RS-${yymm()}-${String(randomInt(100_000)).padStart(5, '0')}`,
          targetType: input.target.type,
          accountId: t.account?.id,
          tenantId: t.tenant?.id,
          kind: input.kind,
          category: input.category,
          internalNote: input.note,
          until,
          createdBy,
          changeRequestId,
          fingerprints: { create: fps },
        },
      });
      await this.audit.append(
        {
          staffId: s.staffId,
          action: `restriction.${change}`,
          targetType: 'RESTRICTION',
          targetId: row.id,
          data: {
            target: input.target,
            kind: input.kind,
            category: input.category,
            until: until?.toISOString() ?? null,
            changeRequestId,
          },
          ip: s.ip,
          requestId: s.requestId,
        },
        tx,
      );
      return row;
    });
    if (input.kind === 'WARNING') return restriction;

    // 3. Effects.
    const effects: Record<string, unknown> = {};
    if (t.account) {
      effects.sessions = await this.endSessions(t.account);
      for (const m of await this.control.membership.findMany({
        where: {
          issuer: t.account.issuer,
          subject: t.account.subject,
          status: 'ACTIVE',
          tenant: { kind: 'COMPANY' },
        },
      }))
        await this.trust
          .recordRestriction(s, m.tenantId, {
            change,
            category: input.category,
            scope: 'member',
            until,
          })
          .catch((e: unknown) =>
            this.logger.warn(`member notice ${m.tenantId}: ${String(e)}`),
          );
      if (input.kind === 'BAN') {
        effects.cancelled = await this.cancelPaying(
          t.owned
            .filter(
              (m) =>
                m.tenant.kind !== 'COMPANY' &&
                this.paying(m.tenant.entitlement),
            )
            .map((m) => m.tenantId),
        );
        effects.handovers = await this.handOver(
          s,
          restriction,
          t.account,
          t.owned,
          input,
        );
      }
    } else {
      effects.suspended = await this.suspendTenant(t.tenant.id, s.staffId);
      if (input.kind === 'BAN' && this.paying(t.tenant.entitlement))
        effects.cancelled = await this.cancelPaying([t.tenant.id]);
    }
    await this.control.staffRestriction.update({
      where: { id: restriction.id },
      data: { effects: effects as Prisma.InputJsonValue },
    });
    await this.audit.checkpoint().catch(() => undefined);
    return { ...restriction, effects: effects as Prisma.JsonValue };
  }

  private async fingerprintsOf(
    t: Awaited<ReturnType<RestrictionsService['target']>>,
  ) {
    const key = this.fpKey();
    const out = new Map<
      string,
      {
        kind:
          'EMAIL' | 'IDP_IDENTITY' | 'CARD' | 'DEVICE' | 'TPM_EK' | 'ENTRA_TID';
        valueHash: string;
      }
    >();
    const add = (
      kind:
        'EMAIL' | 'IDP_IDENTITY' | 'CARD' | 'DEVICE' | 'TPM_EK' | 'ENTRA_TID',
      value: string | null | undefined,
      prehashed = false,
    ) => {
      if (!value) return;
      const valueHash = prehashed ? value : fingerprint(kind, value, key);
      out.set(`${kind}|${valueHash}`, { kind, valueHash });
    };
    if (t.account) {
      const a = t.account;
      add('EMAIL', a.normalizedEmail);
      const contact = await this.control.contactEmail.findUnique({
        where: { issuer_subject: { issuer: a.issuer, subject: a.subject } },
      });
      if (contact?.email && contact.verifiedAt)
        add('EMAIL', normalizeEmail(contact.email));
      for (const m of await this.control.membership.findMany({
        where: { issuer: a.issuer, subject: a.subject },
        select: { email: true },
      }))
        if (m.email && a.idp === 'email') add('EMAIL', normalizeEmail(m.email));
      add('IDP_IDENTITY', a.idpUserHash, true);
      const personal = t.owned.filter((m) => m.tenant.kind === 'PERSONAL');
      for (const m of personal) {
        try {
          const db = await this.tenants.getClient(m.tenantId);
          // Attested identifiers only: the enrolled key, and the TPM EK when attestation passed.
          for (const h of await db.host.findMany({
            select: {
              keyFingerprint: true,
              tpmVerified: true,
              tpmEkFingerprint: true,
            },
          })) {
            add('DEVICE', h.keyFingerprint);
            if (h.tpmVerified) add('TPM_EK', h.tpmEkFingerprint);
          }
        } catch (error) {
          this.logger.warn(
            `device fingerprints of ${m.tenantId}: ${String(error)}`,
          );
        }
      }
      await this.cardsOf(
        t.owned.map((m) => m.tenant.entitlement?.stripeCustomerId),
        add,
      );
    } else {
      add('ENTRA_TID', t.tenant.entraTenantId);
      await this.cardsOf([t.tenant.entitlement?.stripeCustomerId], add);
    }
    return [...out.values()];
  }

  private async cardsOf(
    customers: (string | null | undefined)[],
    add: (k: 'CARD', v: string | null | undefined) => void,
  ) {
    if (!this.stripe.configured) return;
    for (const customer of customers.filter((c): c is string => !!c)) {
      try {
        const methods = await this.stripe
          .client()
          .paymentMethods.list({ customer, type: 'card', limit: 20 });
        for (const pm of methods.data) add('CARD', pm.card?.fingerprint);
      } catch (error) {
        this.logger.warn(`card fingerprints of ${customer}: ${String(error)}`);
      }
    }
  }

  private realmOf(issuer: string): string | null {
    const shared = (this.config.get('AUTH_ISSUERS', { infer: true }) ?? '')
      .split(',')
      .map((x) => x.trim().replace(/\/+$/, ''));
    return shared.includes(issuer.replace(/\/+$/, ''))
      ? (issuer.split('/realms/')[1]?.replace(/\/+$/, '') ?? null)
      : null;
  }

  /** AC-19: sessions end, the user is not disabled, so they can still read why and appeal. */
  private async endSessions(a: { issuer: string; subject: string }) {
    const realm = this.realmOf(a.issuer);
    if (!realm) return { ended: false, reason: 'legacy_realm' };
    try {
      await this.keycloak.logoutUser(realm, a.subject);
      return { ended: true };
    } catch (error) {
      this.logger.warn(`could not end sessions: ${String(error)}`);
      return { ended: false, reason: 'identity_service_unavailable' };
    }
  }

  /** Founder 4 Nov: a ban cancels a paying subscription at once, with no refund for the period. */
  private async cancelPaying(
    tenantIds: string[],
  ): Promise<CancelledSubscription[]> {
    const out: CancelledSubscription[] = [];
    for (const tenantId of tenantIds) {
      const e = await this.control.tenantEntitlement.findUnique({
        where: { tenantId },
      });
      if (!e?.stripeSubscriptionId) continue;
      const base = {
        tenantId,
        subscriptionId: e.stripeSubscriptionId,
        customerId: e.stripeCustomerId,
        currency: null,
        amount: null,
        periodStart: null,
        periodEnd: null,
      };
      if (!this.stripe.configured) {
        out.push({ ...base, error: 'billing_not_configured' });
        continue;
      }
      try {
        const sub = await this.stripe
          .client()
          .subscriptions.cancel(e.stripeSubscriptionId, {
            prorate: false,
            invoice_now: false,
          });
        const item = sub.items.data[0];
        out.push({
          ...base,
          currency: sub.currency,
          amount:
            item?.price.unit_amount != null
              ? item.price.unit_amount * (item.quantity ?? 1)
              : null,
          periodStart: item?.current_period_start ?? null,
          periodEnd: item?.current_period_end ?? null,
        });
      } catch (error) {
        this.logger.error(
          `subscription ${e.stripeSubscriptionId} not cancelled: ${String(error)}`,
        );
        out.push({ ...base, error: 'stripe_cancel_failed' });
      }
    }
    return out;
  }

  private async handOver(
    s: StaffPrincipal,
    r: StaffRestriction,
    a: { issuer: string; subject: string },
    owned: { tenantId: string; tenant: { kind: string } }[],
    input: RestrictionInput,
  ) {
    const out: { tenantId: string; outcome: string }[] = [];
    for (const m of owned.filter((x) => x.tenant.kind === 'COMPANY')) {
      const { soleOwner, candidate } = await this.successionOf(m.tenantId, a);
      if (!soleOwner) continue;
      const choice = input.ownerPlan?.[m.tenantId];
      if (candidate) {
        await this.control.staffOwnerHandover.create({
          data: {
            restrictionId: r.id,
            tenantId: m.tenantId,
            candidateMembershipId: candidate.id,
            dueAt: new Date(Date.now() + HANDOVER_NOTICE_MS),
          },
        });
        out.push({ tenantId: m.tenantId, outcome: 'admin_promoted_in_7_days' });
      } else if (choice === 'ban_org') {
        await this.apply(
          s,
          {
            ...input,
            target: { type: 'TENANT', id: m.tenantId },
            ownerPlan: undefined,
          },
          null,
          r.changeRequestId,
        );
        out.push({ tenantId: m.tenantId, outcome: 'org_banned' });
      } else {
        await this.control.staffOwnerHandover.create({
          data: {
            restrictionId: r.id,
            tenantId: m.tenantId,
            dueAt: new Date(),
            outcome: 'transfer_needed',
          },
        });
        out.push({ tenantId: m.tenantId, outcome: 'transfer_needed' });
      }
    }
    return out;
  }

  /** Org restriction (spec §9.2): the platform's own kill-switch row plus tenant SUSPENDED. */
  private async suspendTenant(tenantId: string, staffId: string) {
    const db = await this.tenants.getClient(tenantId);
    await this.platform.engage(db, tenantId, `staff:${staffId}`);
    await this.control.tenant.update({
      where: { id: tenantId },
      data: { status: 'SUSPENDED' },
    });
    return { tenant: 'SUSPENDED' };
  }

  private async resumeTenant(tenantId: string, staffId: string) {
    const db = await this.tenants.getClient(tenantId);
    await this.platform.release(db, tenantId, `staff:${staffId}`);
    await this.control.tenant.update({
      where: { id: tenantId },
      data: { status: 'ACTIVE' },
    });
  }

  /** Lift a suspension (AC-17: any Admin and above). Bans need the two-person un-ban. */
  async lift(s: StaffPrincipal | 'system', id: string, reason: string) {
    const r = await this.control.staffRestriction.findUnique({ where: { id } });
    if (!r || r.liftedAt)
      throw new NotFoundException({
        code: 'not_found',
        message: 'No such restriction in force.',
      });
    if (r.kind === 'BAN')
      throw new ConflictException({
        code: 'unban_needs_approval',
        message: 'A ban is lifted through an un-ban request.',
      });
    await this.end(s, r, s === 'system' ? 'expired' : 'lifted', reason);
  }

  private async end(
    s: StaffPrincipal | 'system',
    r: StaffRestriction,
    change: 'lifted' | 'unbanned' | 'expired',
    reason: string,
  ) {
    const by = s === 'system' ? 'system:expired' : s.staffId;
    const won = await this.control.staffRestriction.updateMany({
      where: { id: r.id, liftedAt: null },
      data: {
        liftedAt: change === 'expired' && r.until ? r.until : new Date(),
        liftedBy: by,
        liftReason: reason.slice(0, 2000),
      },
    });
    if (won.count !== 1) return false;
    const actor = s === 'system' ? 'system' : s;
    if (r.tenantId && r.targetType === 'TENANT') {
      await this.resumeTenant(r.tenantId, by);
      await this.trust.recordRestriction(actor, r.tenantId, {
        change,
        category: r.category,
        scope: 'workspace',
      });
    } else if (r.accountId) {
      for (const tenantId of await this.trust.personalWorkspacesOf(r.accountId))
        await this.trust.recordRestriction(actor, tenantId, {
          change,
          category: r.category,
          scope: 'self',
        });
    }
    await this.audit.append({
      staffId: s === 'system' ? null : s.staffId,
      action: `restriction.${change}`,
      targetType: 'RESTRICTION',
      targetId: r.id,
      data: { reason: reason.slice(0, 500) },
    });
    return true;
  }

  /**
   * Spec §9.1: un-ban is proposed by an Owner (`restrict.unban.propose`), by the reviewer of an
   * appeal that overturned it (`appeals.review`) or by the reviewer of a false-positive re-signup
   * match (`matches.review`), and approved by another Owner. Checked here, for every caller,
   * failing closed (security review, 4 Nov).
   */
  async proposeUnban(
    s: StaffPrincipal,
    id: string,
    reason: string,
    opts: { fromAppeal?: string; fromMatch?: string } = {},
  ) {
    const needed = opts.fromAppeal
      ? 'appeals.review'
      : opts.fromMatch
        ? 'matches.review'
        : 'restrict.unban.propose';
    let allowed: boolean;
    try {
      allowed = await this.rbac.can(s.staffId, needed);
    } catch (error) {
      throwFailClosed('openfga', error);
    }
    if (!allowed)
      throw new ForbiddenException({
        code: 'permission_required',
        permission: needed,
        message: "Your role doesn't allow proposing an un-ban.",
      });
    const r = await this.control.staffRestriction.findUnique({ where: { id } });
    if (!r || r.liftedAt || r.kind !== 'BAN')
      throw new NotFoundException({
        code: 'not_found',
        message: 'No ban in force with this id.',
      });
    return this.changes.propose(s, {
      kind: 'unban',
      targetId: r.id,
      payload: {
        restrictionId: r.id,
        appealId: opts.fromAppeal ?? null,
        matchId: opts.fromMatch ?? null,
      },
      reason,
    });
  }

  private async executeUnban(cr: StaffChangeRequest, decider: StaffPrincipal) {
    const r = await this.control.staffRestriction.findUniqueOrThrow({
      where: { id: cr.targetId },
    });
    if (r.liftedAt)
      throw new ConflictException({
        code: 'not_in_force',
        message: 'This ban was lifted already.',
      });
    await this.end(decider, r, 'unbanned', cr.reason);
    const credits = await this.creditOverturned(r);
    return { restrictionId: r.id, credits };
  }

  /** Founder 4 Nov: an overturned ban of a paying customer gets a pro-rata credit for the unused time. */
  private async creditOverturned(r: StaffRestriction) {
    const cancelled = (
      (r.effects as { cancelled?: CancelledSubscription[] } | null)
        ?.cancelled ?? []
    ).filter(
      (c) =>
        !c.error && c.customerId && c.amount && c.periodEnd && c.periodStart,
    );
    const out: {
      tenantId: string;
      amount: number;
      currency: string;
      status: string;
    }[] = [];
    for (const c of cancelled) {
      const total = c.periodEnd! - c.periodStart!;
      const unused = Math.max(
        0,
        c.periodEnd! - Math.floor(r.startsAt.getTime() / 1000),
      );
      const amount = Math.round((c.amount! * unused) / total);
      if (amount <= 0) continue;
      if (!this.stripe.configured) {
        out.push({
          tenantId: c.tenantId,
          amount,
          currency: c.currency ?? 'usd',
          status: 'owed_billing_not_configured',
        });
        continue;
      }
      try {
        await this.stripe
          .client()
          .customers.createBalanceTransaction(c.customerId!, {
            amount: -amount,
            currency: c.currency ?? 'usd',
            description: `Pro-rata credit: Manar restriction ${r.code} overturned on appeal`,
          });
        out.push({
          tenantId: c.tenantId,
          amount,
          currency: c.currency ?? 'usd',
          status: 'credited',
        });
      } catch (error) {
        this.logger.error(`credit for ${r.code} failed: ${String(error)}`);
        out.push({
          tenantId: c.tenantId,
          amount,
          currency: c.currency ?? 'usd',
          status: 'credit_failed',
        });
      }
    }
    return out;
  }

  /** Writes the "expired" history for suspensions whose time passed (their power already ended). */
  async recordExpired(): Promise<number> {
    const due = await this.control.staffRestriction.findMany({
      where: { kind: 'SUSPEND', liftedAt: null, until: { lte: new Date() } },
      take: 100,
    });
    let n = 0;
    for (const r of due)
      if (
        await this.end('system', r, 'expired', 'suspension ended').catch(
          () => false,
        )
      )
        n++;
    return n;
  }

  /** Promotes the waiting Admins of handovers past their 7-day notice. */
  async completeHandovers(): Promise<number> {
    const due = await this.control.staffOwnerHandover.findMany({
      where: {
        doneAt: null,
        dueAt: { lte: new Date() },
        candidateMembershipId: { not: null },
      },
    });
    for (const h of due) {
      const r = await this.control.staffRestriction.findUnique({
        where: { id: h.restrictionId },
      });
      const stillBanned = r && !r.liftedAt;
      if (stillBanned)
        await this.control.membership.update({
          where: { id: h.candidateMembershipId! },
          data: { role: 'TENANT_OWNER' },
        });
      await this.control.staffOwnerHandover.update({
        where: { id: h.id },
        data: {
          doneAt: new Date(),
          outcome: stillBanned ? 'promoted' : 'cancelled',
        },
      });
      if (stillBanned)
        await this.trust.recordAction('system', h.tenantId, {
          action: 'owner_promoted_after_restriction',
        });
    }
    return due.length;
  }
}

const refusalText: Record<string, string> = {
  note_too_short: 'Write an internal note of at least 20 characters.',
  bad_duration: 'Choose 1 hour, 24 hours, 7 days or 30 days.',
  bad_category: 'Choose a reason the customer will see.',
  permission_required: "Your role doesn't allow this restriction.",
  warning_required:
    'This is a paying customer: warn them first, wait 48 hours, or ask a second person to approve now.',
  already_banned: 'This account is banned already.',
};

export type { Category };
