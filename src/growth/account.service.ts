import { createHash } from 'node:crypto';
import { AuthCache } from '../database/auth-cache.service';
import {
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
  Optional,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { KeycloakAdminClient } from '../keycloak/keycloak-admin.client';
import { StripeGateway } from '../billing/stripe.gateway';
import { WorkspaceProvisioningService } from '../workspaces/workspace-provisioning.service';
import { DataCollectionService } from '../data-collection/data-collection.service';
import { growthSetting } from './growth.config';
import { ContactEmailService } from '../contact/contact-email.service';
import { MailerService } from './mailer.service';
import { GrowthAuditService } from './growth-audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { zip } from './zip';
import { hasAnotherOwner, withOwnerLocks } from '../users/last-owner';
import { LastOwnerError } from '../users/users.errors';

const DAY_MS = 86_400_000;
const LEASE_MS = 60 * 60 * 1000;
/** Rows kept per big table in an export; the file says so when it was cut. */
const AUDIT_ROWS = 50_000;
const OTHER_ROWS = 10_000;

const json = (v: unknown) =>
  Buffer.from(
    JSON.stringify(
      v,
      (_k, x: unknown) => (typeof x === 'bigint' ? x.toString() : x),
      2,
    ),
  );

/**
 * "Delete my account" (spec #34, launch brief: 7-day grace). Export first, then a graced request
 * the person can cancel. After the grace period the hourly job: cancels the Stripe subscriptions and
 * deletes the Stripe customer (invoices stay with Stripe for tax records), removes the personal
 * devices (REMOVED, so each is told 410 device_removed and gives the person their tools back, also
 * after the database is gone, through a `deleted_workspaces` tombstone) and the personal workspace
 * and its database, leaves the person's company devices protected but unassigned and tells the
 * company's owners and admins, takes the person out of company workspaces (their audit entries
 * stay in those workspaces under that workspace's own retention), removes
 * the Keycloak user, and keeps a PII-free record (subject hashed). The launch-offer claim stays,
 * so a deleted account cannot take a slot twice.
 */
@Injectable()
export class AccountService {
  private readonly logger = new Logger(AccountService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly provisioning: WorkspaceProvisioningService,
    private readonly keycloak: KeycloakAdminClient,
    private readonly stripe: StripeGateway,
    private readonly mailer: MailerService,
    private readonly contact: ContactEmailService,
    private readonly config: ConfigService<AppConfig, true>,
    private readonly data: DataCollectionService,
    private readonly audit: GrowthAuditService,
    @Optional() private readonly authCache?: AuthCache,
  ) {}

  // ---- export ----

  /** A zip of everything Manar holds about the caller's own workspaces. */
  async exportZip(issuer: string, subject: string): Promise<Buffer> {
    const files: { name: string; data: Buffer }[] = [];
    const memberships = await this.control.membership.findMany({
      where: { issuer, subject },
      include: { tenant: true },
    });
    const owned = await this.control.tenant.findMany({
      where: {
        ownerIssuer: issuer,
        ownerSubject: subject,
        kind: { in: ['PERSONAL', 'SAMPLE'] },
        status: 'ACTIVE',
      },
    });
    files.push({
      name: 'account.json',
      data: json({
        exportedAt: new Date().toISOString(),
        memberships: memberships.map((m) => ({
          workspace: m.tenant.name,
          kind: m.tenant.kind,
          role: m.role,
          extraRoles: m.extraRoles,
          status: m.status,
          email: m.email,
          weeklyDigest: m.weeklyDigest,
          timezone: m.timezone,
          locale: m.locale,
          joinedAt: m.createdAt,
        })),
      }),
    });
    for (const [i, t] of owned.entries()) {
      const dir = `workspace-${i + 1}-${t.kind.toLowerCase()}`;
      const db = await this.tenants.getClient(t.id);
      const notes: string[] = [];
      const table = async (
        name: string,
        rows: Promise<unknown[]>,
        cap: number,
      ) => {
        const data = await rows;
        if (data.length >= cap) notes.push(`${name}: newest ${cap} rows only`);
        files.push({ name: `${dir}/${name}.json`, data: json(data) });
      };
      // Whitelist: certificates, key material, tokens and webhook secrets are never exported.
      await table(
        'devices',
        db.host.findMany({
          omit: {
            keyFingerprint: true,
            pendingKeyFingerprint: true,
            tpmEkFingerprint: true,
          },
          take: OTHER_ROWS,
        }),
        OTHER_ROWS,
      );
      await table(
        'agents',
        db.agent.findMany({ take: OTHER_ROWS }),
        OTHER_ROWS,
      );
      await table(
        'policies',
        db.policy.findMany({ include: { versions: true }, take: OTHER_ROWS }),
        OTHER_ROWS,
      );
      await table(
        'approvals',
        db.approvalRequest.findMany({
          orderBy: { createdAt: 'desc' },
          take: OTHER_ROWS,
        }),
        OTHER_ROWS,
      );
      await table(
        'audit-events',
        db.auditEvent.findMany({
          orderBy: { timestamp: 'desc' },
          take: AUDIT_ROWS,
        }),
        AUDIT_ROWS,
      );
      files.push({
        name: `${dir}/README.txt`,
        data: Buffer.from(['Manar workspace export.', ...notes].join('\n')),
      });
    }
    return zip(files);
  }

  // ---- deletion request ----

  async status(issuer: string, subject: string) {
    const row = await this.control.accountDeletion.findUnique({
      where: { issuer_subject: { issuer, subject } },
    });
    // The only owner of a company workspace: the request ended; the person is told.
    if (row?.status === 'REFUSED')
      return { scheduled: false as const, refused: 'sole_owner' as const };
    return row && row.status !== 'DONE'
      ? {
          scheduled: true,
          executeAfter: row.executeAfter,
          requestedAt: row.requestedAt,
        }
      : { scheduled: false as const };
  }

  async request(issuer: string, subject: string, email?: string) {
    try {
      await this.assertNotSoleOwner(issuer, subject);
    } catch (e) {
      if (e instanceof SoleOwnerError)
        throw new ConflictException({
          statusCode: 409,
          code: 'transfer_ownership_first',
        });
      throw e;
    }
    const days = growthSetting(this.config, 'ACCOUNT_DELETION_GRACE_DAYS');
    const executeAfter = new Date(Date.now() + days * DAY_MS);
    const key = { issuer_subject: { issuer, subject } };
    const prior = await this.control.accountDeletion.findUnique({ where: key });
    // A refused request starts over; one that is scheduled or retrying keeps its date.
    const row =
      prior?.status === 'REFUSED'
        ? await this.control.accountDeletion.update({
            where: key,
            data: { status: 'SCHEDULED', executeAfter, summary: undefined },
          })
        : await this.control.accountDeletion.upsert({
            where: key,
            create: { issuer, subject, executeAfter },
            update: {},
          });
    if (email)
      void this.mailer.send({
        to: email,
        subject: 'Your Manar account will be deleted',
        text: `You asked to delete your Manar account. It will be deleted on ${row.executeAfter.toISOString().slice(0, 10)}. Until then you can cancel in Settings, Account. If this was not you, sign in and cancel now and write to support@fixio.ae.\n`,
        html: `<p>You asked to delete your Manar account. It will be deleted on <b>${row.executeAfter.toISOString().slice(0, 10)}</b>.</p><p>Until then you can cancel in Settings, Account. If this was not you, sign in and cancel now and write to support@fixio.ae.</p>`,
      });
    return {
      scheduled: true as const,
      executeAfter: row.executeAfter,
      requestedAt: row.requestedAt,
    };
  }

  async cancel(issuer: string, subject: string) {
    const r = await this.control.accountDeletion.deleteMany({
      where: {
        issuer,
        subject,
        status: { in: ['SCHEDULED', 'FAILED', 'REFUSED'] },
      },
    });
    if (r.count === 0) throw new NotFoundException('no_deletion_scheduled');
    return { scheduled: false as const };
  }

  /** A company workspace must not be left without an owner. */
  private async assertNotSoleOwner(issuer: string, subject: string) {
    const mine = await this.control.membership.findMany({
      where: { issuer, subject, status: 'ACTIVE', tenant: { kind: 'COMPANY' } },
    });
    for (const m of mine) {
      if (m.role !== 'TENANT_OWNER' && !m.extraRoles.includes('TENANT_OWNER'))
        continue;
      if (
        !(await hasAnotherOwner(this.control, m.tenantId, { issuer, subject }))
      )
        throw new SoleOwnerError();
    }
  }

  // ---- the job ----

  async executeDue(
    now = new Date(),
  ): Promise<{ done: number; failed: number }> {
    const due = await this.control.accountDeletion.findMany({
      where: {
        status: { in: ['SCHEDULED', 'FAILED', 'RUNNING'] },
        executeAfter: { lte: now },
      },
      take: 20,
    });
    let done = 0;
    let failed = 0;
    for (const row of due) {
      // Take a one-hour lease; a crashed run is picked up again when it lapses.
      const claimed = await this.control.accountDeletion.updateMany({
        where: {
          id: row.id,
          status: row.status,
          executeAfter: row.executeAfter,
        },
        data: {
          status: 'RUNNING',
          executeAfter: new Date(now.getTime() + LEASE_MS),
        },
      });
      if (claimed.count !== 1) continue;
      try {
        const notify = await this.contact.verified(row.issuer, row.subject);
        const summary = await this.executeOne(row.issuer, row.subject);
        const hash = createHash('sha256')
          .update(`${row.issuer}\n${row.subject}`)
          .digest('hex');
        await this.control.contactEmail.deleteMany({
          where: { issuer: row.issuer, subject: row.subject },
        });
        if (notify)
          void this.mailer.send({
            to: notify,
            subject: 'Your Manar account was deleted',
            text: 'Your Manar account and workspace were deleted as you asked. Thank you for trying Manar.\n',
            html: '<p>Your Manar account and workspace were deleted as you asked. Thank you for trying Manar.</p>',
          });
        await this.control.accountDeletion.update({
          where: { id: row.id },
          data: {
            status: 'DONE',
            subject: `sha256:${hash}`,
            doneAt: new Date(),
            summary: summary as never,
          },
        });
        this.logger.log(
          `account ${row.id} deleted: ${JSON.stringify(summary)}`,
        );
        done++;
      } catch (error) {
        failed++;
        if (error instanceof SoleOwnerError) {
          // Not a glitch to retry every hour: the request ends and the person is told.
          await this.control.accountDeletion.update({
            where: { id: row.id },
            data: { status: 'REFUSED', summary: { reason: 'sole_owner' } },
          });
          const to = await this.contact.verified(row.issuer, row.subject);
          if (to)
            void this.mailer.send({
              to,
              subject: 'Your Manar account was not deleted',
              text: 'Your account deletion was stopped: you are the only owner of a company workspace. Make someone else an owner, then ask again in Settings, Account.\n',
              html: '<p>Your account deletion was stopped: you are the only owner of a company workspace. Make someone else an owner, then ask again in Settings, Account.</p>',
            });
          this.logger.warn(`account ${row.id} deletion refused: sole owner`);
          continue;
        }
        await this.control.accountDeletion.update({
          where: { id: row.id },
          data: {
            status: 'FAILED',
            executeAfter: new Date(now.getTime() + LEASE_MS),
          },
        });
        this.logger.error(
          `account ${row.id} deletion failed, will retry: ${String(error)}`,
        );
      }
    }
    return { done, failed };
  }

  private async executeOne(issuer: string, subject: string) {
    await this.assertNotSoleOwner(issuer, subject); // changed since the request: stop, keep the account
    // 0. The one step that can still refuse, before anything is destroyed. The person stops being
    //    an owner of ALL their companies in one transaction under the per-workspace locks of a role
    //    revoke (withOwnerLocks): every last-owner check first, then every write, so a company
    //    that refuses leaves the person owner of the others too. Two owners deleting their accounts
    //    at once cannot orphan a company: the loser is refused here, with the account untouched.
    //    Rows are marked REMOVED, not deleted, so step 3 still finds the companies (also on the
    //    hourly retry) and the final delete takes them away.
    const ownedCompanies = (
      await this.control.membership.findMany({
        where: {
          issuer,
          subject,
          status: 'ACTIVE',
          tenant: { kind: 'COMPANY' },
        },
      })
    )
      .filter(
        (m) =>
          m.role === 'TENANT_OWNER' || m.extraRoles.includes('TENANT_OWNER'),
      )
      .map((m) => m.tenantId);
    if (ownedCompanies.length > 0) {
      try {
        await withOwnerLocks(
          this.control,
          ownedCompanies,
          { issuer, subject },
          (tx) =>
            tx.membership.updateMany({
              where: { issuer, subject, tenantId: { in: ownedCompanies } },
              data: { status: 'REMOVED' },
            }),
        );
      } catch (error) {
        if (error instanceof LastOwnerError) throw new SoleOwnerError();
        throw error;
      }
      // Right after the commit that removed the owner roles, not only at the end of the deletion.
      void this.authCache?.invalidate();
    }
    const owned = await this.control.tenant.findMany({
      where: {
        ownerIssuer: issuer,
        ownerSubject: subject,
        kind: { in: ['PERSONAL', 'SAMPLE'] },
      },
    });
    const summary = {
      personalWorkspaces: 0,
      companyMembershipsRemoved: 0,
      stripeCustomers: 0,
      devicesRemoved: 0,
      companyDevicesUnassigned: 0,
      keycloakUserRemoved: false,
    };
    for (const t of owned) {
      // 1. Stripe first: if it fails, nothing has been destroyed and the job retries.
      const ent = await this.control.tenantEntitlement.findUnique({
        where: { tenantId: t.id },
      });
      if (ent?.stripeSubscriptionId && this.stripe.configured)
        await this.stripe
          .client()
          .subscriptions.cancel(ent.stripeSubscriptionId)
          .catch(ignoreMissing);
      if (ent?.stripeCustomerId && this.stripe.configured) {
        await this.stripe
          .client()
          .customers.del(ent.stripeCustomerId)
          .catch(ignoreMissing);
        summary.stripeCustomers++;
      }
      // 2. The tombstone first (it only counts once the workspace row is gone), then the devices
      //    REMOVED, not REVOKED: a removed device is told 410 device_removed and gives the person
      //    their tools back; a revoked one would keep blocking them. Then the workspace (DELETED
      //    stops every guard) and its database.
      await this.control.deletedWorkspace.upsert({
        where: { slug: t.slug },
        create: { slug: t.slug, reason: 'account_deleted' },
        update: { reason: 'account_deleted' },
      });
      if (t.status === 'ACTIVE') {
        const db = await this.tenants.getClient(t.id);
        summary.devicesRemoved += (
          await db.host.updateMany({
            where: { status: { not: 'REMOVED' } },
            data: {
              status: 'REMOVED',
              removedAt: new Date(),
              removedReason: 'account_deleted',
            },
          })
        ).count;
      }
      await this.provisioning.deleteOwnedWorkspace(t.id);
      if (t.kind === 'PERSONAL') summary.personalWorkspaces++;
    }
    // 3. Company workspaces keep existing: the person just leaves. Their company devices belong to
    //    the company: they stay protected, unassigned, and the owners and admins are told.
    summary.companyDevicesUnassigned = await this.unassignCompanyDevices(
      issuer,
      subject,
    );
    summary.companyMembershipsRemoved = (
      await this.control.membership.deleteMany({ where: { issuer, subject } })
    ).count;
    void this.authCache?.invalidate(); // after the delete: the person's cached roles must go now
    // 4. Product improvement data: stored samples and the PostHog person.
    await this.data.deleteUserData(issuer, subject);
    await this.control.userDataPreference.deleteMany({
      where: { issuer, subject },
    });
    // 5. The sign-in account itself, in the hosted realm only. A customer-hosted install's realm
    //    belongs to the customer (and may write through to their directory): its users stay.
    const realm =
      this.config.get('MANAR_DEPLOYMENT', { infer: true }) === 'hosted'
        ? realmOf(issuer)
        : null;
    if (realm) {
      await this.keycloak.deleteUser(realm, subject);
      summary.keycloakUserRemoved = true;
    }
    return summary;
  }

  /**
   * Company devices assigned to the person (in a company, the host's `ownerSubject`) lose that
   * person: no longer "their own" device, so approvals go to approvers, and protection is untouched.
   * Audited in each company and mailed to its owners and admins. Idempotent for the hourly retry.
   */
  private async unassignCompanyDevices(
    issuer: string,
    subject: string,
  ): Promise<number> {
    const memberships = await this.control.membership.findMany({
      where: { issuer, subject, tenant: { kind: 'COMPANY', status: 'ACTIVE' } },
      include: { tenant: true },
    });
    let total = 0;
    for (const m of memberships) {
      const db = await this.tenants.getClient(m.tenantId);
      const hosts = await db.host.findMany({
        where: { ownerSubject: subject, status: { not: 'REMOVED' } },
        select: { id: true },
      });
      const { count } = await db.host.updateMany({
        where: { ownerSubject: subject, status: { not: 'REMOVED' } },
        data: { ownerSubject: null, unassignedAt: new Date() },
      });
      total += count;
      const actor = { type: 'system' as const, id: 'system:account-deletion' };
      await this.audit.record(
        m.tenantId,
        AUDIT_EVENT_TYPES.MEMBER_ACCOUNT_DELETED,
        actor,
        { devicesUnassigned: count },
      );
      for (const h of hosts) {
        await this.audit.record(
          m.tenantId,
          AUDIT_EVENT_TYPES.HOST_UNASSIGNED,
          actor,
          { hostId: h.id, reason: 'account_deleted' },
        );
      }
      const admins = await this.control.membership.findMany({
        where: {
          tenantId: m.tenantId,
          status: 'ACTIVE',
          NOT: { issuer, subject },
          OR: [
            { role: { in: [...COMPANY_ADMIN_ROLES] } },
            { extraRoles: { hasSome: [...COMPANY_ADMIN_ROLES] } },
          ],
        },
      });
      const text =
        count > 0
          ? `A member of your Manar workspace deleted their account. ${count} device(s) they used stay protected and are now unassigned: assign them to someone or release them in Devices.\n`
          : 'A member of your Manar workspace deleted their account. They used no devices in it.\n';
      for (const a of admins) {
        const to = await this.contact.verified(a.issuer, a.subject);
        if (to)
          void this.mailer.send({
            to,
            subject: 'A member deleted their Manar account',
            text,
            html: `<p>${text.trim()}</p>`,
          });
      }
    }
    return total;
  }
}

const COMPANY_ADMIN_ROLES = ['TENANT_OWNER', 'SECURITY_ADMIN'] as const;

const ignoreMissing = (e: unknown) => {
  if ((e as { code?: string }).code === 'resource_missing') return;
  throw e;
};

/** `https://auth.example/realms/manar` -> `manar`. */
export function realmOf(issuer: string): string | null {
  try {
    const m = /^\/realms\/([^/]+)\/?$/.exec(new URL(issuer).pathname);
    return m?.[1] ?? null;
  } catch {
    return null;
  }
}

/** The person is the only owner of a company workspace. */
export class SoleOwnerError extends Error {
  constructor() {
    super('sole_owner');
  }
}
