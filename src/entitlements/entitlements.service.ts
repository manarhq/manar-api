import { ForbiddenException, Injectable } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';

/** The transaction client handed to an interactive tenant-DB transaction. */
export type TenantTx = Parameters<
  Parameters<TenantPrismaClient['$transaction']>[0]
>[0];

/**
 * LOCAL STUB of the billing track's `EntitlementsService` (launch brief section 2). Same name,
 * same two methods, so callers (devices today) code against the final interface. When the
 * billing track merges, its `src/entitlements/` replaces this directory; nothing else changes.
 *
 * Until then NOTHING is enforced unless MANAR_STUB_ENFORCE_PLAN_LIMITS=true (existing pilot
 * tenants must not suddenly get the free personal caps); with it set every tenant has them.
 */
export type EntitlementLimit = 'devices' | 'agents' | 'cloudAgents';

export interface Entitlements {
  plan: 'free' | 'pro' | 'company_trial' | 'company' | 'enterprise';
  status: string;
  limits: {
    devices: number;
    agents: number;
    cloudAgents: number;
    auditDays: number;
  };
  features: string[];
  trialEndsAt?: Date;
}

export class PlanLimitError extends Error {
  constructor(
    readonly limit: EntitlementLimit,
    readonly current: number,
    readonly max: number,
    readonly upgradeUrl: string,
  ) {
    super(`plan limit reached: ${limit} ${current}/${max}`);
  }

  /** HTTP 403 `{ code: 'plan_limit_reached', limit, current, max, upgradeUrl }`. */
  toHttp(): ForbiddenException {
    return new ForbiddenException({
      code: 'plan_limit_reached',
      limit: this.limit,
      current: this.current,
      max: this.max,
      upgradeUrl: this.upgradeUrl,
    });
  }
}

@Injectable()
export class EntitlementsService {
  // eslint-disable-next-line @typescript-eslint/require-await -- same async signature as the real service
  async get(tenantId: string): Promise<Entitlements> {
    void tenantId;
    return {
      plan: 'free',
      status: 'active',
      limits: { devices: 3, agents: 10, cloudAgents: 1, auditDays: 30 },
      features: [],
    };
  }

  /**
   * `current` is the amount in use AFTER the action (existing + the one being added); it throws
   * when that is over the plan's maximum.
   */
  async assertWithin(
    tenantId: string,
    limit: EntitlementLimit,
    current: number,
  ): Promise<void> {
    if (process.env.MANAR_STUB_ENFORCE_PLAN_LIMITS !== 'true') return;
    const max = (await this.get(tenantId)).limits[limit];
    if (current > max) {
      throw new PlanLimitError(limit, current, max, '/settings/billing');
    }
  }

  /**
   * Count + assert inside the caller's tenant-DB transaction, under a per-database advisory
   * lock, so parallel adds cannot all pass the check. Call it right before the insert, in the
   * same transaction as the insert. `count` runs after the lock is held.
   */
  async assertWithinLocked(
    tx: TenantTx,
    tenantId: string,
    limit: EntitlementLimit,
    count: () => Promise<number>,
  ): Promise<void> {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`plan-limit:${limit}`}))`;
    await this.assertWithin(tenantId, limit, (await count()) + 1);
  }

  /** `assertWithinLocked` + `create` in one transaction of its own. */
  async withinLimit<T>(
    tenantId: string,
    limit: EntitlementLimit,
    tenantClient: TenantPrismaClient,
    count: (tx: TenantTx) => Promise<number>,
    create: (tx: TenantTx) => Promise<T>,
  ): Promise<T> {
    return tenantClient.$transaction(async (tx) => {
      await this.assertWithinLocked(tx, tenantId, limit, () => count(tx));
      return create(tx);
    });
  }
}
