import { Injectable, Logger } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { AUDIT_EVENT_TYPES, type AuditActor } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import type { AppConfig } from '../config/env.validation';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { LicenseService } from '../licensing/license.service';
import type {
  Prisma,
  PrismaClient as TenantPrismaClient,
} from '../generated/tenant-client/client';
import { PlanLimitError } from './plan-limit.error';
import {
  ENTERPRISE_ONLY_FEATURES,
  PLAN_TABLE,
  type Allowance,
  type LimitName,
  type Limits,
  type PlanName,
} from './plans';

export type EntitlementState = 'active' | 'past_due' | 'read_only' | 'frozen';

export interface Entitlement {
  plan: PlanName;
  status: EntitlementState;
  /** `null` = unlimited. */
  limits: Limits;
  features: string[];
  /** Included per month; per seat on Company plans. */
  allowance: Allowance;
  trialEndsAt?: Date;
  /** Company yearly: seats paid for the year. */
  committedSeats?: number;
}

export interface EntitlementPatch {
  plan?: PlanName;
  status?: EntitlementState;
  trialEndsAt?: Date | null;
  stripeCustomerId?: string;
  stripeSubscriptionId?: string | null;
  billingInterval?: string | null;
  committedSeats?: number | null;
}

const DAY_MS = 86_400_000;

/**
 * Per-tenant plan, limits and features. Limits come from the plan table (`plans.ts`); Enterprise
 * takes them from the signed licence. A tenant with no row is on the free plan. A company trial
 * past its end date reads as `read_only` without any job having to flip it.
 */
@Injectable()
export class EntitlementsService {
  private readonly logger = new Logger(EntitlementsService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly config: ConfigService<AppConfig, true>,
    private readonly audit: AuditService,
    private readonly tenants: TenantDatabaseManager,
    private readonly moduleRef: ModuleRef,
  ) {}

  async get(tenantId: string): Promise<Entitlement> {
    const row = await this.control.tenantEntitlement.findUnique({
      where: { tenantId },
    });
    if (!row) return { plan: 'free', status: 'active', ...PLAN_TABLE.free };
    const ended = !!row.trialEndsAt && row.trialEndsAt.getTime() <= Date.now();
    // The personal trial drops softly to Free at its end, with no job to flip it.
    if (row.plan === 'trial' && (ended || !row.trialEndsAt))
      return { plan: 'free', status: 'active', ...PLAN_TABLE.free };
    let status: EntitlementState = row.status;
    if (row.plan === 'company_trial' && ended) status = 'read_only';
    // A dispute freezes paid features: Free limits and allowance, safety untouched.
    const base =
      status === 'frozen' ? PLAN_TABLE.free : await this.planBase(row.plan);
    return {
      plan: row.plan,
      status,
      ...base,
      ...((row.plan === 'company_trial' || row.plan === 'trial') &&
      row.trialEndsAt
        ? { trialEndsAt: row.trialEndsAt }
        : {}),
      ...(row.committedSeats ? { committedSeats: row.committedSeats } : {}),
    };
  }

  /**
   * Throws `PlanLimitError` when one more of `limit` does not fit: `current` is how many the
   * tenant already has, so a free tenant with 3 devices cannot add a 4th. A read-only workspace
   * cannot add anything.
   */
  async assertWithin(
    tenantId: string,
    limit: LimitName,
    current: number,
  ): Promise<void> {
    this.check(await this.get(tenantId), limit, current);
  }

  /**
   * Count, check and create as one step: parallel requests cannot all pass the check and then
   * overshoot the cap. Runs in one tenant-DB transaction holding an advisory lock per limit (the
   * tenant has its own database, so the lock is per tenant). Use this wherever something is
   * created under a cap; `assertWithin` is for read-only checks.
   */
  async withinLimit<T>(
    tenantId: string,
    limit: LimitName,
    tenantClient: TenantPrismaClient,
    count: (tx: Prisma.TransactionClient) => Promise<number>,
    create: (tx: Prisma.TransactionClient) => Promise<T>,
  ): Promise<T> {
    const entitlement = await this.get(tenantId);
    return tenantClient.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`plan-limit:${limit}`}))`;
      this.check(entitlement, limit, await count(tx));
      return create(tx);
    });
  }

  /**
   * `withinLimit` for a caller already inside a tenant-DB transaction: takes the same lock, then
   * counts what exists and checks it. Call it right before the insert, in that transaction.
   */
  async assertWithinLocked(
    tx: Prisma.TransactionClient,
    tenantId: string,
    limit: LimitName,
    count: () => Promise<number>,
  ): Promise<void> {
    const entitlement = await this.get(tenantId);
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`plan-limit:${limit}`}))`;
    this.check(entitlement, limit, await count());
  }

  private check(e: Entitlement, limit: LimitName, current: number): void {
    const max = e.status === 'read_only' ? 0 : e.limits[limit];
    if (max === null || current < max) return;
    throw new PlanLimitError(limit, current, max, this.upgradeUrl());
  }

  /** Earliest audit timestamp this tenant may search; null = no limit. Older events are hidden, not deleted. */
  async auditSearchFloor(tenantId: string): Promise<Date | null> {
    const { limits } = await this.get(tenantId);
    return limits.auditDays === null
      ? null
      : new Date(Date.now() - limits.auditDays * DAY_MS);
  }

  /** Writes the patch and audits `billing.plan.changed` when the plan moved. */
  async change(
    tenantId: string,
    patch: EntitlementPatch,
    actor: AuditActor,
    source: string,
  ): Promise<Entitlement> {
    const before = await this.get(tenantId);
    await this.control.tenantEntitlement.upsert({
      where: { tenantId },
      create: { tenantId, ...patch },
      update: patch,
    });
    const after = await this.get(tenantId);
    if (after.plan !== before.plan) {
      try {
        const client = await this.tenants.getClient(tenantId);
        await this.audit.recordSafely(client, tenantId, {
          eventType: AUDIT_EVENT_TYPES.BILLING_PLAN_CHANGED,
          actor,
          data: { from: before.plan, to: after.plan, source },
        });
      } catch (error) {
        this.logger.error(
          `billing.plan.changed audit failed for tenant "${tenantId}": ${String(error)}`,
        );
      }
    }
    return after;
  }

  upgradeUrl(): string {
    const base =
      this.config.get('BILLING_CONSOLE_URL', { infer: true }) ??
      'http://localhost:3001';
    return `${base.replace(/\/$/, '')}/settings/billing`;
  }

  private async planBase(
    plan: PlanName,
  ): Promise<{ limits: Limits; features: string[]; allowance: Allowance }> {
    if (plan !== 'enterprise') return PLAN_TABLE[plan];
    // Enterprise comes from the signed licence; without a valid one it is as small as Free.
    // LicenseService lives in the HTTP app only (LicensingModule), so it is looked up, not injected.
    const lic = await this.moduleRef
      .get(LicenseService, { strict: false })
      .status()
      .catch(() => null);
    const valid = lic?.limits && ['valid', 'expiring'].includes(lic.status);
    if (!lic || !valid) return PLAN_TABLE.free;
    return {
      limits: {
        devices: null,
        agents: lic.limits?.agents ?? null,
        cloudAgents: null,
        auditDays: null,
      },
      features: [...new Set([...lic.features, ...ENTERPRISE_ONLY_FEATURES])],
      // The contract's credit pool is a `contract` lot; the monthly allowance is Company's.
      allowance: PLAN_TABLE.company.allowance,
    };
  }
}
