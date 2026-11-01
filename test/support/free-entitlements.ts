import { EntitlementsService } from '../../src/billing/entitlements.service';

/** The real service with no billing row for any tenant, so every tenant is on the free plan. */
export function freeEntitlements(): EntitlementsService {
  return new EntitlementsService(
    { tenantEntitlement: { findUnique: () => Promise.resolve(null) } } as never,
    { get: () => 'http://localhost:3001' } as never,
    {} as never,
    {} as never,
    {} as never,
  );
}
