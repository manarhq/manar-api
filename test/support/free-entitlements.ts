import { EntitlementsService } from '../../src/billing/entitlements.service';
import type { ControlPrismaService } from '../../src/database/control-prisma.service';

function entitlements(
  row: { plan: string; status: string; trialEndsAt?: Date } | null,
) {
  return new EntitlementsService(
    { tenantEntitlement: { findUnique: () => Promise.resolve(row) } } as never,
    { get: () => 'http://localhost:3001' } as never,
    {} as never,
    {} as never,
    {} as never,
  );
}

/**
 * The real service with every tenant on a non-paying plan with a 3-device cap: the personal trial
 * (Free itself has 1 device since pay-as-you-go pricing). The device specs were written against a
 * cap of 3, which is what they exercise.
 */
export function freeEntitlements(): EntitlementsService {
  return entitlements({
    plan: 'trial',
    status: 'active',
    trialEndsAt: new Date(Date.now() + 14 * 86_400_000),
  });
}

/** The real service with an active Company row for every tenant (no device cap). */
export function companyEntitlements(): EntitlementsService {
  return entitlements({ plan: 'company', status: 'active' });
}

/**
 * Puts a provisioned tenant on the Company plan (an active `TenantEntitlement` row), for specs that
 * create more agents or devices than Free allows. The row goes with the tenant (cascade).
 */
export async function onCompanyPlan(
  control: Pick<ControlPrismaService, 'tenantEntitlement'>,
  tenantId: string,
): Promise<void> {
  await control.tenantEntitlement.upsert({
    where: { tenantId },
    create: { tenantId, plan: 'company', status: 'active' },
    update: { plan: 'company', status: 'active' },
  });
}
