import { HttpException, Injectable, Logger } from '@nestjs/common';
import type { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  InjectThrottlerOptions,
  InjectThrottlerStorage,
  ThrottlerGuard,
} from '@nestjs/throttler';
import type {
  ThrottlerModuleOptions,
  ThrottlerRequest,
  ThrottlerStorage,
} from '@nestjs/throttler';
import type { RequestWithAuthContext } from '../auth/auth-context';
import { requestedWorkspace } from '../auth/jwt-auth.guard';
import { MembershipService } from '../auth/membership.service';
import {
  extractBearerToken,
  TokenVerifierService,
} from '../auth/token-verifier.service';
import { isHealthRoutePath } from '../health/health.routes';
import { isCloudMcpPath } from '../cloud-mcp/cloud-mcp.config';

/**
 * Phase 12a: rate-limits the human JWT surface **per tenant**, not per
 * caller IP (`ThrottlerGuard`'s own default `getTracker`) -- a burst from
 * one tenant's dashboard users behind a shared corporate NAT/VPN egress IP
 * must not exhaust the same bucket as an unrelated tenant, and a bucket
 * keyed by tenant is exactly what stops one tenant's traffic from starving
 * another's regardless of network topology on either side.
 *
 * This guard is registered globally (`APP_GUARD`, `AppModule`), which
 * means it runs *before* any controller-level `JwtAuthGuard` -- so
 * `request.authContext` (attached by `JwtAuthGuard`) is not yet available
 * to key off directly. Instead this mirrors `JwtAuthGuard`'s own first two
 * steps exactly (`docs/human-auth.md`): read the token's `iss` claim
 * *without* verifying the signature (this is a rate-limit partition key,
 * not a trust decision -- an attacker presenting a forged token at worst
 * gets its own separate bucket, and still fails real authentication
 * immediately afterward in `JwtAuthGuard` itself), then resolve it against
 * `KnownIssuerRegistry` to a real `tenantId`. Falls back to the caller's IP
 * for any request this can't resolve a tenant for (no/malformed
 * Authorization header, unrecognized issuer, or an unauthenticated route)
 * -- rate limiting still applies, just not tenant-scoped, which is no
 * worse than the framework's own default for those cases.
 */
@Injectable()
export class TenantThrottlerGuard extends ThrottlerGuard {
  private readonly logger = new Logger(TenantThrottlerGuard.name);

  constructor(
    @InjectThrottlerOptions() options: ThrottlerModuleOptions,
    @InjectThrottlerStorage() storage: ThrottlerStorage,
    reflector: Reflector,
    private readonly tokenVerifier: TokenVerifierService,
    private readonly memberships: MembershipService,
  ) {
    super(options, storage, reflector);
  }

  /**
   * Never rate-limit the kubelet's own probe endpoints.
   *
   * Release 2026-11-11 reliability fix. This guard is a global `APP_GUARD`
   * (`RateLimitModule`), so before this override it ran on **every** route
   * including `/health/live` — and `ThrottlerGuard.handleRequest` calls
   * `ThrottlerStorage.increment` unguarded (@nestjs/throttler 6.5.0), while
   * `RedisThrottlerStorageService.getClient` throws when Redis is
   * unreachable. The result was that a Redis outage turned `/health/live`
   * into a 500, the kubelet read that as a dead process, and it restarted
   * **every replica** — converting a degraded-but-serving dependency into a
   * full outage plus a crash-loop. A liveness probe must depend on nothing
   * but this process, and a readiness probe must be able to *report* a
   * dependency failure rather than be blocked by one.
   *
   * Exempting these paths costs nothing security-wise: they are
   * unauthenticated, take no user input, return a fixed-shape body, and are
   * reachable only from inside the cluster (`templates/networkpolicy.yaml`
   * restricts `httpPort` ingress to manar-web and the ingress controller).
   *
   * Matched by request path rather than by `@SkipThrottle()` deliberately:
   * `@SkipThrottle()` with no arguments only skips a throttler *named*
   * `default`, and this application's only throttler is named `human`
   * (`RateLimitModule`) — so the decorator form would silently not skip
   * anything, which is exactly the failure mode this fix exists to remove.
   * `shouldSkip` short-circuits every configured throttler by name-agnostic
   * construction.
   */
  protected override async shouldSkip(
    context: ExecutionContext,
  ): Promise<boolean> {
    if (context.getType() !== 'http') return super.shouldSkip(context);

    const { req } = this.getRequestResponse(context);
    const url: unknown = req.url;
    if (typeof url === 'string' && isHealthRoutePath(url)) return true;
    // Cloud agents have their own per-agent and per-IP limits (CloudMcpAuthGuard).
    if (typeof url === 'string' && isCloudMcpPath(url)) return true;

    return super.shouldSkip(context);
  }

  /**
   * Fail **open** when the throttler's Redis storage is unreachable: log
   * it, allow the request through, and let every other guard on the route
   * run exactly as it normally would.
   *
   * **This is a deliberate availability-over-enforcement trade-off — see
   * docs/release/2026-11-11/fix-notes-reliability.md.** The reasoning:
   *
   * - Rate limiting in this codebase is *availability protection* (one
   *   tenant's burst must not starve another's — see this class's own doc
   *   comment), not an authorization control. Nothing here decides who may
   *   do what; `JwtAuthGuard`, `RolesGuard`, `AgentMtlsGuard`,
   *   `BffServiceGuard`, `PolicyEngine`, and OpenFGA do, and every one of
   *   them runs *after* this guard and is completely untouched by this
   *   catch. A Redis outage therefore cannot turn into an authorization
   *   bypass, only into a temporarily unenforced quota.
   * - Failing *closed* would mean a Redis outage returns 500 for 100% of
   *   authenticated traffic on every replica — i.e. the rate limiter, whose
   *   entire purpose is to keep the API available under load, would itself
   *   become the thing that takes the API down. That is strictly worse than
   *   the risk it protects against.
   * - The abuse window is bounded and observable: Redis being down is
   *   loud (this logs every occurrence at `error`, and
   *   `RedisThrottlerStorageService` logs its own connection errors), and
   *   the kill-switch surface (`src/kill-switches/`) remains available as
   *   the operator's real "stop this tenant now" control, since it depends
   *   on Postgres rather than Redis.
   *
   * Since 9 Oct 2026 the storage itself falls back to per-instance
   * in-memory limits (`LocalFallbackThrottlerStorage`), so a Redis outage
   * no longer reaches this catch and tenants stay limited; this path is
   * left for a failure of the fallback itself.
   *
   * Only *storage/infrastructure* failures fail open. A genuine
   * `ThrottlerException` — the 429 raised by
   * `ThrottlerGuard.throwThrottlingException` once a caller is over its
   * limit — is an `HttpException` and is re-thrown untouched, so the normal
   * enforcement path is completely unchanged when Redis is healthy.
   */
  protected override async handleRequest(
    requestProps: ThrottlerRequest,
  ): Promise<boolean> {
    try {
      return await super.handleRequest(requestProps);
    } catch (error) {
      // Real 429s (and anything else deliberately raised as an HTTP
      // response by the throttler pipeline) are the enforcement path
      // working, not a storage failure — never swallow them.
      if (error instanceof HttpException) throw error;

      this.logger.error(
        `Rate-limit storage unavailable for throttler "${requestProps.throttler.name}" — allowing the request through unlimited (fail-open, see this guard's doc comment): ${errorMessage(error)}`,
      );
      return true;
    }
  }

  protected override async getTracker(
    req: RequestWithAuthContext,
  ): Promise<string> {
    if (req.authContext?.tenant?.id) {
      return `tenant:${req.authContext.tenant.id}`;
    }

    // Not authenticated yet: verify the token, then resolve the workspace the same way
    // JwtAuthGuard will (Membership). Anything that does not resolve falls back to the IP.
    const token = extractBearerToken(req.headers.authorization);
    if (token) {
      const identity = await this.tokenVerifier.tryVerify(token);
      if (identity) {
        try {
          const workspace = await this.memberships.resolveActive({
            subject: identity.subject,
            requestedTenantId: requestedWorkspace(req.headers),
            boundTenantId: identity.boundTenant?.id,
          });
          return `tenant:${workspace.tenantId}`;
        } catch {
          // no usable membership: not a tenant bucket
        }
      }
    }

    return `ip:${req.ip}`;
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
