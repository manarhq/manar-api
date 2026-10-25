import { createHash } from 'node:crypto';
import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectThrottlerStorage } from '@nestjs/throttler';
import type { ThrottlerStorage } from '@nestjs/throttler';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { decodeJwt, errors as joseErrors, jwtVerify } from 'jose';
import type { JWTPayload } from 'jose';
import type { AgentContext } from '../agent-mtls/agent-context';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { JwksCacheService } from '../auth/jwks-cache.service';
import { ACCEPTED_SIGNING_ALGORITHMS } from '../auth/jwt-auth.guard';
import { KnownIssuerRegistry } from '../auth/known-issuer-registry.service';
import { failClosed, throwFailClosed } from '../common/fail-closed/fail-closed';
import type { AppConfig } from '../config/env.validation';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { recordCloudMcpRejection } from '../metrics/metrics';
import { CloudAgentsService } from './cloud-agents.service';
import {
  AGENT_ROLE_CLAIM,
  PRE_REGISTERED_CLIENT_PREFIX,
  cloudMcpMetadataUrl,
  cloudMcpResourceUrl,
  cloudMcpRole,
  cloudMcpScope,
  cloudMcpSettings,
} from './cloud-mcp.config';

const SLUG = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
const RATE_WINDOW_MS = 60_000;
/**
 * Refused requests (no token, or a token refused) per minute: per caller address and tenant, and
 * per tenant across all addresses. A separate budget: it never touches the per-agent budget of
 * accepted calls, so failures cannot use up an agent's limit.
 */
const FAILURES_PER_ADDRESS = 60;
const FAILURES_PER_TENANT = 600;
/** A refused, validly signed token is audited once a minute per tenant, client and reason. */
const AUDIT_DEDUP_MS = 60_000;
const LOG_SAMPLE_MS = 60_000;

export type CloudMcpRequest = FastifyRequest & {
  cloudAgent?: { context: AgentContext; taskId: string };
};

type Rejection = {
  status: 401 | 403;
  reason: string;
  /** Set once the realm signature verified: the refusal goes to that tenant's audit chain. */
  tenantId?: string;
};

/**
 * The OAuth gate of the public MCP endpoint `/mcp/<tenantSlug>/<agentSlug>`
 * (docs/cloud-agents.md, MCP authorization spec).
 *
 * The tenant comes from the token issuer, matched against provisioned
 * realms; the path slug only has to agree (else 401). Signature against the
 * realm JWKS (pinned RSA, no clock skew), audience = this agent's exact MCP
 * URL and no other agent's, `typ: Bearer`. Then the agent: ACTIVE, kind
 * CLOUD; the person: holds the agent role (`manar-agent-<slug>`); the client:
 * the agent's own with the agent scope (pre-registered, or the self-registered
 * client a tenant admin confirmed; the first eligible one waits for that and
 * gets 403 `cloud_client_pending_approval`).
 *
 * Budgets: an accepted call spends only its agent's budget. A refused call
 * spends only the failure budgets (per caller address and tenant, per tenant);
 * past them it is 429 and nothing is audited. `request.ip` is the real caller
 * when `MANAR_TRUSTED_PROXY_CIDRS` lists the proxies (src/config/trusted-proxy.ts).
 *
 * Refusals before the signature verified never touch a tenant database: a
 * metric and a log line sampled per address and tenant. Refusals after it are
 * audited in the issuer's tenant at most once a minute per client and reason
 * (reason, client id, a SHA-256 prefix; never the token). Kill switches,
 * quarantine and task liveness are checked by the governed MCP server on
 * every call (`AgentTaskAccessService`).
 */
@Injectable()
export class CloudMcpAuthGuard implements CanActivate {
  private readonly logger = new Logger(CloudMcpAuthGuard.name);
  // ponytail: per-process sampling map, cleared when large; good enough for log volume control.
  private readonly lastLogged = new Map<string, number>();
  // ponytail: per-replica memory of blocked failure budgets (learned from the shared store on the
  // refusal that crossed the limit); another replica pays one full check before it learns too.
  private readonly blockedUntil = new Map<string, number>();

  constructor(
    private readonly config: ConfigService<AppConfig, true>,
    private readonly knownIssuers: KnownIssuerRegistry,
    private readonly jwksCache: JwksCacheService,
    private readonly tenants: TenantDatabaseManager,
    private readonly audit: AuditService,
    private readonly cloudAgents: CloudAgentsService,
    @InjectThrottlerStorage() private readonly limits: ThrottlerStorage,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<CloudMcpRequest>();
    const reply = context.switchToHttp().getResponse<FastifyReply>();
    const params = request.params as Record<string, string | undefined>;
    const tenantSlug = params.tenantSlug ?? '';
    const agentSlug = params.agentSlug ?? '';
    const settings = cloudMcpSettings(this.config);
    const host = settings.host;
    if (!host || !SLUG.test(tenantSlug) || !SLUG.test(agentSlug)) {
      throw new NotFoundException();
    }

    const resource = cloudMcpResourceUrl(host, tenantSlug, agentSlug);
    const scope = cloudMcpScope(agentSlug);
    const challenge = (error?: string) =>
      [
        `Bearer resource_metadata="${cloudMcpMetadataUrl(host, tenantSlug, agentSlug)}"`,
        `scope="${scope}"`,
        ...(error ? [`error="${error}"`] : []),
      ].join(', ');

    const token = /^Bearer\s+(\S+)\s*$/i.exec(
      request.headers.authorization ?? '',
    )?.[1];
    const addressKey = `cloud-mcp-fail:${tenantSlug}:${request.ip}`;
    const tenantKey = `cloud-mcp-fail-tenant:${tenantSlug}`;
    if (!token) {
      // OAuth discovery starts here: always the cheap 401, counted for this caller only.
      recordCloudMcpRejection('missing_token');
      await this.count(addressKey, FAILURES_PER_ADDRESS);
      reply.header('WWW-Authenticate', challenge());
      throw new UnauthorizedException('Bearer token required');
    }
    // A caller over its failure budget is turned away before any key, database or Keycloak work.
    this.shedIfBlocked(reply, addressKey);

    const refuse = async (
      rejection: Rejection,
      unverified: JWTPayload,
      tenantBudget: boolean,
    ): Promise<never> => {
      recordCloudMcpRejection(rejection.reason);
      const blocked =
        (await this.count(addressKey, FAILURES_PER_ADDRESS)) ||
        (tenantBudget && (await this.count(tenantKey, FAILURES_PER_TENANT)));
      if (blocked) this.tooMany(reply, blocked);
      if (rejection.tenantId) {
        await this.recordRejection(
          rejection.tenantId,
          agentSlug,
          token,
          unverified,
          rejection.reason,
        );
      } else {
        this.sampledLog(tenantSlug, request.ip, rejection.reason);
      }
      reply.header(
        'WWW-Authenticate',
        challenge(
          rejection.status === 401 ? 'invalid_token' : 'insufficient_scope',
        ),
      );
      throw rejection.status === 401
        ? new UnauthorizedException({
            statusCode: 401,
            reason: rejection.reason,
          })
        : new ForbiddenException({ statusCode: 403, reason: rejection.reason });
    };

    let unverified: JWTPayload;
    try {
      unverified = decodeJwt(token);
    } catch {
      // Not a JWT: cheap to refuse, so it counts for this caller only.
      return refuse({ status: 401, reason: 'malformed_token' }, {}, false);
    }
    const outcome = await this.check(
      token,
      unverified,
      tenantSlug,
      agentSlug,
      `https://${host}/mcp/`,
      resource,
      scope,
    );
    if ('status' in outcome) return refuse(outcome, unverified, true);

    const { context: agentContext } = outcome;
    await this.limit(
      reply,
      `cloud-mcp:${agentContext.tenant.id}:${agentContext.agent.id}`,
      settings.ratePerMinute,
    );
    request.cloudAgent = outcome;
    return true;
  }

  /**
   * Counts one refusal in a failure budget. Returns the seconds the key stays blocked (0 when it
   * is not), and remembers a block so the next request is shed before any work.
   */
  private async count(key: string, limit: number): Promise<number> {
    const usage = await failClosed('rate-limit-store', () =>
      this.limits.increment(
        key,
        RATE_WINDOW_MS,
        limit,
        RATE_WINDOW_MS,
        'cloud-mcp',
      ),
    );
    if (!usage.isBlocked) return 0;
    const seconds = Math.max(1, Math.ceil(usage.timeToBlockExpire));
    if (this.blockedUntil.size > 10_000) this.blockedUntil.clear();
    this.blockedUntil.set(key, Date.now() + seconds * 1000);
    return seconds;
  }

  private shedIfBlocked(reply: FastifyReply, key: string): void {
    const until = this.blockedUntil.get(key) ?? 0;
    if (until > Date.now()) {
      this.tooMany(reply, Math.ceil((until - Date.now()) / 1000));
    }
  }

  private tooMany(reply: FastifyReply, seconds: number): never {
    recordCloudMcpRejection('rate_limited');
    reply.header('Retry-After', String(Math.max(1, seconds)));
    throw new HttpException(
      { statusCode: 429, reason: 'rate_limited' },
      HttpStatus.TOO_MANY_REQUESTS,
    );
  }

  private async limit(reply: FastifyReply, key: string, limit: number) {
    const usage = await failClosed('rate-limit-store', () =>
      this.limits.increment(
        key,
        RATE_WINDOW_MS,
        limit,
        RATE_WINDOW_MS,
        'cloud-mcp',
      ),
    );
    if (usage.isBlocked) {
      recordCloudMcpRejection('rate_limited');
      reply.header(
        'Retry-After',
        String(Math.max(1, Math.ceil(usage.timeToBlockExpire))),
      );
      throw new HttpException(
        { statusCode: 429, reason: 'rate_limited' },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }

  private async check(
    token: string,
    unverified: JWTPayload,
    tenantSlug: string,
    agentSlug: string,
    mcpPrefix: string,
    resource: string,
    scope: string,
  ): Promise<Rejection | { context: AgentContext; taskId: string }> {
    const issuer = typeof unverified.iss === 'string' ? unverified.iss : '';
    const known = issuer
      ? await failClosed('control-db', () =>
          this.knownIssuers.resolveByIssuer(issuer),
        )
      : null;
    if (!known) return { status: 401, reason: 'unknown_issuer' };
    // The tenant is the issuer's; a path naming another tenant is refused.
    if (known.tenantSlug !== tenantSlug) {
      return { status: 401, reason: 'issuer_tenant_mismatch' };
    }

    let payload: JWTPayload;
    // jose checks the signature before any claim, so claim failures below are post-signature.
    const verified = { status: 401 as const, tenantId: known.tenantId };
    try {
      ({ payload } = await jwtVerify(
        token,
        this.jwksCache.getJwks(known.issuerUrl),
        {
          issuer: known.issuerUrl,
          audience: resource,
          algorithms: [...ACCEPTED_SIGNING_ALGORITHMS],
        },
      ));
    } catch (error) {
      if (error instanceof joseErrors.JWTExpired) {
        return { ...verified, reason: 'token_expired' };
      }
      if (error instanceof joseErrors.JWTClaimValidationFailed) {
        return {
          ...verified,
          reason:
            error.claim === 'aud' ? 'wrong_audience' : `invalid_${error.claim}`,
        };
      }
      if (
        error instanceof joseErrors.JOSEError &&
        !(error instanceof joseErrors.JWKSTimeout)
      ) {
        return { status: 401, reason: 'invalid_token' };
      }
      // The realm's JWKS could not be fetched: fail closed (503), not "bad token".
      throwFailClosed('keycloak-jwks', error);
    }
    if (payload.typ !== 'Bearer') {
      return { ...verified, reason: 'not_an_access_token' };
    }
    // A token for several agents is a token for none of them.
    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (audiences.some((a) => a?.startsWith(mcpPrefix) && a !== resource)) {
      return { ...verified, reason: 'foreign_audience' };
    }

    const forbidden = (reason: string): Rejection => ({
      status: 403,
      reason,
      tenantId: known.tenantId,
    });
    const tenantClient = await failClosed('tenant-db', () =>
      this.tenants.getClient(known.tenantId),
    );
    const agent = await failClosed('tenant-db', () =>
      tenantClient.agent.findUnique({
        where: { slug: agentSlug },
        include: { cloudBinding: true },
      }),
    );
    const binding = agent?.cloudBinding;
    if (!agent || agent.kind !== 'CLOUD' || !binding) {
      return forbidden('unknown_agent');
    }
    if (agent.status !== 'ACTIVE') return forbidden('agent_not_active');

    const roles = payload[AGENT_ROLE_CLAIM];
    if (!Array.isArray(roles) || !roles.includes(cloudMcpRole(agentSlug))) {
      return forbidden('user_not_allowed');
    }
    const scopes =
      typeof payload.scope === 'string' ? payload.scope.split(' ') : [];
    const clientId = typeof payload.azp === 'string' ? payload.azp : '';
    if (!clientId || !scopes.includes(scope)) {
      return forbidden('unknown_client');
    }
    if (binding.oauthClientId) {
      if (clientId !== binding.oauthClientId)
        return forbidden('unknown_client');
    } else {
      // ChatGPT: the first eligible self-registered client waits for a tenant admin.
      const proposal =
        binding.platform === 'CHATGPT' &&
        !clientId.startsWith(PRE_REGISTERED_CLIENT_PREFIX)
          ? await failClosed('keycloak-admin', () =>
              this.cloudAgents.proposeDcrClient(
                known.tenantId,
                agent.id,
                clientId,
              ),
            )
          : 'refused';
      return forbidden(
        proposal === 'pending'
          ? 'cloud_client_pending_approval'
          : 'unknown_client',
      );
    }

    return {
      taskId: binding.taskId,
      context: {
        tenant: { id: known.tenantId, slug: known.tenantSlug },
        agent: { id: agent.id, slug: agent.slug, identifier: agent.identifier },
      },
    };
  }

  /** Only for tokens whose realm signature verified; best effort, never changes the refusal. */
  private async recordRejection(
    tenantId: string,
    agentSlug: string,
    token: string,
    unverified: JWTPayload,
    reason: string,
  ): Promise<void> {
    try {
      const clientId =
        typeof unverified.azp === 'string' ? unverified.azp.slice(0, 128) : '';
      // Once a minute per (tenant, client, reason): any validly signed realm token could
      // otherwise write a hash-chain row per request. The rest are the metric only.
      const seen = await this.limits.increment(
        `cloud-mcp-audit:${tenantId}:${clientId}:${reason}`,
        AUDIT_DEDUP_MS,
        Number.MAX_SAFE_INTEGER,
        AUDIT_DEDUP_MS,
        'cloud-mcp',
      );
      if (seen.totalHits > 1) return;
      const tenantClient = await this.tenants.getClient(tenantId);
      await this.audit.recordSafely(tenantClient, tenantId, {
        eventType: AUDIT_EVENT_TYPES.CLOUD_MCP_TOKEN_REJECTED,
        actor: { type: 'system', id: 'system:cloud-mcp' },
        data: {
          reason,
          agentSlug,
          clientId:
            typeof unverified.azp === 'string'
              ? unverified.azp.slice(0, 128)
              : null,
          tokenSha256Prefix: createHash('sha256')
            .update(token)
            .digest('hex')
            .slice(0, 16),
        },
      });
    } catch {
      // Audit is best effort here; the request is refused either way.
    }
  }

  private sampledLog(tenantSlug: string, ip: string, reason: string): void {
    const key = `${tenantSlug}|${ip}`;
    const now = Date.now();
    if (now - (this.lastLogged.get(key) ?? 0) < LOG_SAMPLE_MS) return;
    if (this.lastLogged.size > 10_000) this.lastLogged.clear();
    this.lastLogged.set(key, now);
    this.logger.warn(
      `Refused an unverified token for tenant "${tenantSlug}" from ${ip}: ${reason} (sampled, one line per minute per address and tenant)`,
    );
  }
}
