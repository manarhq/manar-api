import { Injectable, Logger } from '@nestjs/common';
import { z } from 'zod';
import { StripeGateway } from '../../billing/stripe.gateway';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { Prisma } from '../../generated/control-client/client';
import type { StaffPermission } from '../rbac/permissions';
import {
  personStatus,
  type PersonStatus,
} from '../restrictions/restriction-rules';
import { maskEmail } from './masking';
import { classifyQuery } from './search';

const PLAN_RANK: Record<string, number> = {
  free: 0,
  pro: 1,
  company_trial: 2,
  company: 3,
  enterprise: 4,
};
const GROUP_SIZE = 5;

export const PeopleQuery = z.object({
  q: z.string().max(120).optional(),
  status: z
    .enum(['ACTIVE', 'WARNED', 'SUSPENDED', 'BANNED', 'DELETION_PENDING'])
    .optional(),
  plan: z
    .enum(['free', 'pro', 'company_trial', 'company', 'enterprise'])
    .optional(),
  idp: z.enum(['microsoft', 'github', 'email']).optional(),
  signedUpFrom: z.coerce.date().optional(),
  signedUpTo: z.coerce.date().optional(),
  hasDevices: z.boolean().optional(),
  tag: z.string().max(40).optional(),
  cursor: z.string().max(200).optional(),
  limit: z.number().int().min(1).max(100).default(50),
});
export type PeopleQuery = z.infer<typeof PeopleQuery>;

export const OrgsQuery = z.object({
  q: z.string().max(120).optional(),
  plan: z
    .enum(['free', 'pro', 'company_trial', 'company', 'enterprise'])
    .optional(),
  status: z.enum(['ACTIVE', 'SUSPENDED']).optional(),
  tag: z.string().max(40).optional(),
  cursor: z.string().max(200).optional(),
  limit: z.number().int().min(1).max(100).default(50),
});
export type OrgsQuery = z.infer<typeof OrgsQuery>;

/** Keyset cursor over (createdAt DESC, id DESC). */
const encodeCursor = (at: Date, id: string) =>
  Buffer.from(`${at.toISOString()}|${id}`).toString('base64url');
function decodeCursor(c?: string): { at: Date; id: string } | null {
  if (!c) return null;
  const [at, id] = Buffer.from(c, 'base64url').toString().split('|');
  const d = new Date(at ?? '');
  return id && !Number.isNaN(d.getTime()) ? { at: d, id } : null;
}
/** ILIKE pattern with the user's wildcards escaped. */
const like = (q: string) => `%${q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;

export interface PersonRow {
  id: string;
  name: string;
  email: string | null;
  idp: string | null;
  plan: string;
  status: PersonStatus;
  workspaces: number;
  devices: number;
  signedUpAt: Date;
  lastActiveAt: Date;
  lastCountry: string | null;
  riskScore: number;
  tags: string[];
}

/**
 * The people and org index and the search box (DESK spec §7). Postgres only (AC-3): trigram
 * indexes, keyset pagination, everything masked (founder 4 Nov: PII masked for every role until a
 * logged reveal). Search result lists are not record views, so they go to the staff chain only
 * (AC-37, done by the audit interceptor).
 */
@Injectable()
export class StaffIndexService {
  private readonly logger = new Logger(StaffIndexService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly stripe: StripeGateway,
  ) {}

  async search(raw: string, can: ReadonlySet<StaffPermission>) {
    const { kind, value } = classifyQuery(raw);
    const out = {
      kind,
      people: [] as PersonRow[],
      orgs: [] as Awaited<ReturnType<StaffIndexService['queryOrgs']>>['items'],
      devices: [] as {
        tenantId: string;
        tenantName: string;
        hostId: string;
        hostname: string | null;
        os: string | null;
      }[],
      invoices: [] as {
        id: string;
        number: string | null;
        status: string | null;
        amountDue: number;
        currency: string;
        tenantId: string | null;
        tenantName: string | null;
      }[],
      references: [] as {
        reference: string;
        at: Date;
        status: number;
        route: string;
        accountId: string | null;
        tenantId: string | null;
      }[],
    };
    if (kind === 'empty') return out;
    const peopleIds = new Set<string>();
    const orgIds = new Set<string>();

    if (kind === 'reference' && can.has('errors.view')) {
      const r = await this.control.staffErrorReference.findUnique({
        where: { reference: value },
      });
      if (r) {
        const account =
          r.issuer && r.subject && r.issuer !== 'staff'
            ? await this.control.account.findUnique({
                where: {
                  issuer_subject: { issuer: r.issuer, subject: r.subject },
                },
                select: { id: true },
              })
            : null;
        out.references.push({
          reference: r.reference,
          at: r.at,
          status: r.status,
          route: r.route,
          accountId: account?.id ?? null,
          tenantId: r.tenantId,
        });
        if (account) peopleIds.add(account.id);
        if (r.tenantId) orgIds.add(r.tenantId);
      }
    }
    if (kind === 'stripe_id') {
      const ent = await this.control.tenantEntitlement.findFirst({
        where: {
          OR: [{ stripeCustomerId: value }, { stripeSubscriptionId: value }],
        },
        select: { tenantId: true },
      });
      if (ent) orgIds.add(ent.tenantId);
    }
    if (kind === 'stripe_invoice' && this.stripe.configured) {
      try {
        const stripe = this.stripe.client();
        const invoice = value.startsWith('in_')
          ? await stripe.invoices.retrieve(value)
          : (
              await stripe.invoices.search({
                query: `number:'${value.replace(/'/g, '')}'`,
                limit: 1,
              })
            ).data[0];
        if (invoice) {
          const customer =
            typeof invoice.customer === 'string'
              ? invoice.customer
              : invoice.customer?.id;
          const ent = customer
            ? await this.control.tenantEntitlement.findUnique({
                where: { stripeCustomerId: customer },
                include: { tenant: { select: { name: true } } },
              })
            : null;
          out.invoices.push({
            id: invoice.id ?? value,
            number: invoice.number ?? null,
            status: invoice.status ?? null,
            amountDue: invoice.amount_due,
            currency: invoice.currency,
            tenantId: ent?.tenantId ?? null,
            tenantName: ent?.tenant.name ?? null,
          });
          if (ent) orgIds.add(ent.tenantId);
        }
      } catch (error) {
        this.logger.warn(`invoice lookup failed: ${String(error)}`);
      }
    }
    if (kind === 'uuid') {
      const [a, t, d] = await Promise.all([
        this.control.account.findUnique({
          where: { id: value },
          select: { id: true },
        }),
        this.control.tenant.findUnique({
          where: { id: value },
          select: { id: true, kind: true },
        }),
        this.control.staffDeviceIndex.findFirst({ where: { hostId: value } }),
      ]);
      if (a) peopleIds.add(a.id);
      if (t) orgIds.add(t.id);
      if (d) out.devices.push(await this.deviceRow(d));
    }
    if (kind === 'email') {
      const rows = await this.control.$queryRaw<{ id: string }[]>`
        SELECT a.id FROM accounts a WHERE a."normalizedEmail" = ${value}
        UNION
        SELECT a.id FROM accounts a JOIN contact_emails c ON c.issuer = a.issuer AND c.subject = a.subject
          WHERE lower(c.email) = ${value}
        LIMIT ${GROUP_SIZE}`;
      for (const r of rows) peopleIds.add(r.id);
    }
    if (kind === 'text' || (kind === 'email' && peopleIds.size === 0)) {
      const pattern = like(value);
      const [people, orgs, devices] = await Promise.all([
        this.control.$queryRaw<{ id: string }[]>`
          SELECT id FROM accounts
          WHERE "displayName" ILIKE ${pattern} OR "normalizedEmail" ILIKE ${pattern}
          ORDER BY similarity("displayName", ${value}) DESC, "lastSeenAt" DESC LIMIT ${GROUP_SIZE}`,
        this.control.$queryRaw<{ id: string }[]>`
          SELECT id FROM tenants
          WHERE kind = 'COMPANY' AND (name ILIKE ${pattern} OR slug ILIKE ${pattern})
          ORDER BY similarity(name, ${value}) DESC LIMIT ${GROUP_SIZE}`,
        this.control.staffDeviceIndex.findMany({
          where: { hostname: { contains: value, mode: 'insensitive' } },
          take: GROUP_SIZE,
        }),
      ]);
      for (const p of people) peopleIds.add(p.id);
      for (const o of orgs) orgIds.add(o.id);
      for (const d of devices) out.devices.push(await this.deviceRow(d));
    }
    if (peopleIds.size)
      out.people = await this.peopleByIds([...peopleIds].slice(0, GROUP_SIZE));
    if (orgIds.size)
      out.orgs = (
        await this.queryOrgs(
          { limit: GROUP_SIZE },
          [...orgIds].slice(0, GROUP_SIZE),
        )
      ).items;
    return out;
  }

  private async deviceRow(d: {
    tenantId: string;
    hostId: string;
    hostname: string | null;
    os: string | null;
  }) {
    const t = await this.control.tenant.findUnique({
      where: { id: d.tenantId },
      select: { name: true },
    });
    return {
      tenantId: d.tenantId,
      tenantName: t?.name ?? '',
      hostId: d.hostId,
      hostname: d.hostname,
      os: d.os,
    };
  }

  async queryPeople(
    f: PeopleQuery,
  ): Promise<{ items: PersonRow[]; nextCursor: string | null }> {
    const cursor = decodeCursor(f.cursor);
    const conds: Prisma.Sql[] = [Prisma.sql`TRUE`];
    if (cursor)
      conds.push(
        Prisma.sql`(a."createdAt", a.id) < (${cursor.at}, ${cursor.id})`,
      );
    if (f.q) {
      const c = classifyQuery(f.q);
      conds.push(
        c.kind === 'email'
          ? Prisma.sql`a."normalizedEmail" = ${c.value}`
          : Prisma.sql`(a."displayName" ILIKE ${like(c.value)} OR a."normalizedEmail" ILIKE ${like(c.value)})`,
      );
    }
    if (f.idp) conds.push(Prisma.sql`a.idp = ${f.idp}`);
    if (f.signedUpFrom)
      conds.push(Prisma.sql`a."createdAt" >= ${f.signedUpFrom}`);
    if (f.signedUpTo) conds.push(Prisma.sql`a."createdAt" < ${f.signedUpTo}`);
    if (f.tag)
      conds.push(
        Prisma.sql`EXISTS (SELECT 1 FROM staff_tags t WHERE t."targetType" = 'ACCOUNT' AND t."targetId" = a.id AND t.tag = ${f.tag})`,
      );
    if (f.hasDevices !== undefined)
      conds.push(
        Prisma.sql`${f.hasDevices ? Prisma.sql`` : Prisma.sql`NOT`} EXISTS (SELECT 1 FROM staff_device_index d WHERE d."ownerSubject" = a.subject AND d.status <> 'REMOVED')`,
      );
    if (f.plan)
      conds.push(Prisma.sql`EXISTS (
        SELECT 1 FROM memberships m JOIN tenant_entitlements e ON e."tenantId" = m."tenantId"
        WHERE m.issuer = a.issuer AND m.subject = a.subject AND m.status = 'ACTIVE' AND m.role = 'TENANT_OWNER' AND e.plan::text = ${f.plan})`);
    const inForce = (kind: string) => Prisma.sql`EXISTS (
      SELECT 1 FROM staff_restrictions r WHERE r."accountId" = a.id AND r.kind::text = ${kind} AND r."liftedAt" IS NULL
      AND r."startsAt" <= now() AND (r.kind <> 'SUSPEND' OR r.until > now()))`;
    const deleting = Prisma.sql`EXISTS (SELECT 1 FROM account_deletions x WHERE x.issuer = a.issuer AND x.subject = a.subject AND x.status = 'SCHEDULED')`;
    if (f.status === 'BANNED') conds.push(inForce('BAN'));
    if (f.status === 'SUSPENDED')
      conds.push(Prisma.sql`${inForce('SUSPEND')} AND NOT ${inForce('BAN')}`);
    if (f.status === 'DELETION_PENDING')
      conds.push(
        Prisma.sql`${deleting} AND NOT ${inForce('BAN')} AND NOT ${inForce('SUSPEND')}`,
      );
    if (f.status === 'WARNED')
      conds.push(
        Prisma.sql`${inForce('WARNING')} AND NOT ${inForce('BAN')} AND NOT ${inForce('SUSPEND')} AND NOT ${deleting}`,
      );
    if (f.status === 'ACTIVE')
      conds.push(
        Prisma.sql`NOT ${inForce('WARNING')} AND NOT ${inForce('BAN')} AND NOT ${inForce('SUSPEND')} AND NOT ${deleting}`,
      );
    const rows = await this.control.$queryRaw<
      { id: string; createdAt: Date }[]
    >`
      SELECT a.id, a."createdAt" FROM accounts a
      WHERE ${Prisma.join(conds, ' AND ')}
      ORDER BY a."createdAt" DESC, a.id DESC
      LIMIT ${f.limit + 1}`;
    const page = rows.slice(0, f.limit);
    const items = await this.peopleByIds(page.map((r) => r.id));
    const last = page[page.length - 1];
    return {
      items,
      nextCursor:
        rows.length > f.limit && last
          ? encodeCursor(last.createdAt, last.id)
          : null,
    };
  }

  /** List rows for these accounts, in the given order, masked. */
  async peopleByIds(ids: string[]): Promise<PersonRow[]> {
    if (!ids.length) return [];
    const now = new Date();
    const accounts = await this.control.account.findMany({
      where: { id: { in: ids } },
      include: { restrictions: { where: { liftedAt: null } } },
    });
    const pairs = accounts.map((a) => ({
      issuer: a.issuer,
      subject: a.subject,
    }));
    const [memberships, devices, tags, deletions] = await Promise.all([
      this.control.membership.findMany({
        where: { OR: pairs, status: 'ACTIVE' },
        select: {
          issuer: true,
          subject: true,
          role: true,
          tenant: { select: { entitlement: { select: { plan: true } } } },
        },
      }),
      this.control.staffDeviceIndex.groupBy({
        by: ['ownerSubject'],
        where: {
          ownerSubject: { in: accounts.map((a) => a.subject) },
          status: { not: 'REMOVED' },
        },
        _count: { _all: true },
      }),
      this.control.staffTag.findMany({
        where: { targetType: 'ACCOUNT', targetId: { in: ids } },
      }),
      this.control.accountDeletion.findMany({
        where: { OR: pairs, status: 'SCHEDULED' },
        select: { issuer: true, subject: true },
      }),
    ]);
    const key = (x: { issuer: string; subject: string }) =>
      `${x.issuer}|${x.subject}`;
    const byId = new Map(
      accounts.map((a) => {
        const mine = memberships.filter((m) => key(m) === key(a));
        const plan = mine
          .filter((m) => m.role === 'TENANT_OWNER')
          .map((m) => m.tenant.entitlement?.plan ?? 'free')
          .sort((x, y) => PLAN_RANK[y]! - PLAN_RANK[x]!)[0];
        const row: PersonRow = {
          id: a.id,
          name: a.displayName,
          email: maskEmail(a.normalizedEmail),
          idp: a.idp,
          plan: plan ?? 'free',
          status: personStatus(a.restrictions, now, {
            deletionPending: deletions.some((d) => key(d) === key(a)),
          }),
          workspaces: mine.length,
          devices:
            devices.find((d) => d.ownerSubject === a.subject)?._count._all ?? 0,
          signedUpAt: a.createdAt,
          lastActiveAt: a.lastSeenAt,
          lastCountry: a.lastCountry,
          riskScore: a.riskScore,
          tags: tags.filter((t) => t.targetId === a.id).map((t) => t.tag),
        };
        return [a.id, row] as const;
      }),
    );
    return ids.flatMap((id) => (byId.has(id) ? [byId.get(id)!] : []));
  }

  async queryOrgs(f: OrgsQuery, onlyIds?: string[]) {
    const cursor = decodeCursor(f.cursor);
    const where: Prisma.TenantWhereInput = {
      kind: 'COMPANY',
      ...(onlyIds ? { id: { in: onlyIds } } : {}),
      ...(f.status
        ? { status: f.status }
        : { status: { in: ['ACTIVE', 'SUSPENDED'] } }),
      ...(f.plan ? { entitlement: { plan: f.plan } } : {}),
      ...(f.q
        ? {
            OR: [
              { name: { contains: f.q, mode: 'insensitive' } },
              { slug: { contains: f.q, mode: 'insensitive' } },
            ],
          }
        : {}),
      ...(cursor
        ? {
            OR: [
              { createdAt: { lt: cursor.at } },
              { createdAt: cursor.at, id: { lt: cursor.id } },
            ],
          }
        : {}),
    };
    if (f.tag) {
      const tagged = await this.control.staffTag.findMany({
        where: { targetType: 'TENANT', tag: f.tag },
        select: { targetId: true },
      });
      where.id = {
        in: tagged
          .map((t) => t.targetId)
          .filter((id) => !onlyIds || onlyIds.includes(id)),
      };
    }
    const tenants = await this.control.tenant.findMany({
      where,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: f.limit + 1,
      include: {
        entitlement: true,
        memberships: {
          where: { status: 'ACTIVE' },
          select: { role: true, email: true },
        },
      },
    });
    const page = tenants.slice(0, f.limit);
    const ids = page.map((t) => t.id);
    const [devices, tags, restrictions] = await Promise.all([
      this.control.staffDeviceIndex.groupBy({
        by: ['tenantId'],
        where: { tenantId: { in: ids }, status: { not: 'REMOVED' } },
        _count: { _all: true },
      }),
      this.control.staffTag.findMany({
        where: { targetType: 'TENANT', targetId: { in: ids } },
      }),
      this.control.staffRestriction.findMany({
        where: { targetType: 'TENANT', tenantId: { in: ids }, liftedAt: null },
      }),
    ]);
    const now = new Date();
    const items = page.map((t) => ({
      id: t.id,
      name: t.name,
      slug: t.slug,
      plan: t.entitlement?.plan ?? 'free',
      billingStatus: t.entitlement?.status ?? 'active',
      trialEndsAt: t.entitlement?.trialEndsAt ?? null,
      members: t.memberships.length,
      devices: devices.find((d) => d.tenantId === t.id)?._count._all ?? 0,
      owners: t.memberships
        .filter((m) => m.role === 'TENANT_OWNER')
        .map((m) => maskEmail(m.email)),
      entraLinked: !!t.entraTenantId,
      createdAt: t.createdAt,
      status: personStatus(
        restrictions.filter((r) => r.tenantId === t.id),
        now,
      ),
      tags: tags.filter((x) => x.targetId === t.id).map((x) => x.tag),
    }));
    const last = page[page.length - 1];
    return {
      items,
      nextCursor:
        tenants.length > f.limit && last
          ? encodeCursor(last.createdAt, last.id)
          : null,
    };
  }
}
