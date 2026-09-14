/**
 * The health surface's route constants, in a **leaf module with no imports
 * of its own** so anything in the codebase can depend on them without
 * dragging in `HealthController` (and, transitively, every dependency the
 * readiness check probes) or risking an import cycle.
 *
 * This exists specifically so `TenantThrottlerGuard`
 * (`src/rate-limit/tenant-throttler.guard.ts`) can exempt the kubelet's
 * probe paths from rate limiting without importing the health module — see
 * that guard's `shouldSkip` doc comment for why that exemption is a
 * liveness-safety requirement and not a convenience.
 */

/** `@Controller()` prefix for `HealthController`. */
export const HEALTH_ROUTE_PREFIX = 'health';

/** Process liveness — the kubelet's `livenessProbe` target. */
export const HEALTH_LIVE_PATH = `/${HEALTH_ROUTE_PREFIX}/live`;

/** Dependency-aware readiness — the kubelet's `readinessProbe` target. */
export const HEALTH_READY_PATH = `/${HEALTH_ROUTE_PREFIX}/ready`;

/**
 * True for any request path served by `HealthController`.
 *
 * Matches on the path only: a Fastify request's `url` carries the query
 * string too (`/health/ready?foo=1`), and an exact-equality check against
 * `HEALTH_READY_PATH` would therefore miss a probe configured with one.
 * Anchored at the start and followed by `/` or end-of-path, so a route
 * such as `/healthcheck-proxy` or `/tenants/health` can never accidentally
 * buy itself a rate-limit exemption.
 */
export function isHealthRoutePath(rawUrl: string): boolean {
  const path = rawUrl.split('?', 1)[0] ?? rawUrl;
  const normalized = path.length > 1 ? path.replace(/\/+$/, '') : path;
  return (
    normalized === `/${HEALTH_ROUTE_PREFIX}` ||
    normalized.startsWith(`/${HEALTH_ROUTE_PREFIX}/`)
  );
}
