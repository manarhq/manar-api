import { createHash } from 'node:crypto';
import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
  NotFoundException,
  PayloadTooLargeException,
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
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import {
  cloudMcpMetadataUrl,
  cloudMcpResourceUrl,
  cloudMcpScope,
  cloudMcpSettings,
} from './cloud-mcp.config';

const SLUG = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
const RATE_WINDOW_MS = 60_000;
/** Client ids Manar gives pre-registered (Copilot Studio) clients. */
export const PRE_REGISTERED_CLIENT_PREFIX = 'manar-cloud-';

export type CloudMcpRequest = FastifyRequest & {
  cloudAgent?: { context: AgentContext; taskId: string };
};

type Rejection = { status: 401 | 403; reason: string };

/**
 * The OAuth gate of the public MCP endpoint `/mcp/<tenantSlug>/<agentSlug>`
 * (docs/cloud-agents.md, MCP authorization spec). The tenant comes from the
 * verified token's issuer, matched against the control DB's provisioned
 * realms; the path slug only has to agree with it (else 401). Then:
 * signature against the realm JWKS (pinned RSA algorithms, no clock skew),
 * audience = this agent's exact MCP URL, `typ: Bearer`, then the agent must
 * be an ACTIVE `CLOUD` agent whose binding names the token's client (`azp`)
 * and scope (else 403). Per-agent rate limit last.
 *
 * Every refusal of a presented token is audited in the tenant the path names
 * (reason, unverified client id, a SHA-256 prefix of the token; never the
 * token). A request with no token is the normal first step of discovery and
 * is not audited. Kill switches, quarantine and task liveness are checked by
 * the governed MCP server itself on every call (`AgentTaskAccessService`).
 */
@Injectable()
export class CloudMcpAuthGuard implements CanActivate {
  constructor(
    private readonly config: ConfigService<AppConfig, true>,
    private readonly knownIssuers: KnownIssuerRegistry,
    private readonly jwksCache: JwksCacheService,
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly audit: AuditService,
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
    if (
      Number(request.headers['content-length'] ?? 0) > settings.maxBodyBytes
    ) {
      throw new PayloadTooLargeException();
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
    if (!token) {
      reply.header('WWW-Authenticate', challenge());
      throw new UnauthorizedException('Bearer token required');
    }

    let unverified: JWTPayload = {};
    try {
      unverified = decodeJwt(token);
    } catch {
      // Not a JWT: refused below as unknown_issuer.
    }
    const outcome = await this.check(
      token,
      unverified,
      tenantSlug,
      agentSlug,
      resource,
      scope,
    );
    if ('status' in outcome) {
      await this.recordRejection(
        tenantSlug,
        agentSlug,
        token,
        unverified,
        outcome.reason,
      );
      reply.header(
        'WWW-Authenticate',
        challenge(
          outcome.status === 401 ? 'invalid_token' : 'insufficient_scope',
        ),
      );
      throw outcome.status === 401
        ? new UnauthorizedException({ statusCode: 401, reason: outcome.reason })
        : new ForbiddenException({ statusCode: 403, reason: outcome.reason });
    }

    const { context: agentContext } = outcome;
    const usage = await failClosed('rate-limit-store', () =>
      this.limits.increment(
        `cloud-mcp:${agentContext.tenant.id}:${agentContext.agent.id}`,
        RATE_WINDOW_MS,
        settings.ratePerMinute,
        RATE_WINDOW_MS,
        'cloud-mcp',
      ),
    );
    if (usage.isBlocked) {
      reply.header(
        'Retry-After',
        String(Math.max(1, Math.ceil(usage.timeToBlockExpire))),
      );
      throw new HttpException(
        { statusCode: 429, reason: 'rate_limited' },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    request.cloudAgent = outcome;
    return true;
  }

  private async check(
    token: string,
    unverified: JWTPayload,
    tenantSlug: string,
    agentSlug: string,
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
        return { status: 401, reason: 'token_expired' };
      }
      if (error instanceof joseErrors.JWTClaimValidationFailed) {
        return {
          status: 401,
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
    if (payload.typ !== 'Bearer')
      return { status: 401, reason: 'not_an_access_token' };

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
      return { status: 403, reason: 'unknown_agent' };
    }
    if (agent.status !== 'ACTIVE')
      return { status: 403, reason: 'agent_not_active' };

    const clientId = typeof payload.azp === 'string' ? payload.azp : '';
    const clientAllowed = binding.oauthClientId
      ? clientId === binding.oauthClientId
      : // Registered by the vendor itself (DCR): any realm client except the console's and the
        // pre-registered clients of other cloud agents (which also see realm optional scopes).
        clientId !== '' &&
        clientId !== this.config.get('KEYCLOAK_CLIENT_ID', { infer: true }) &&
        !clientId.startsWith(PRE_REGISTERED_CLIENT_PREFIX);
    const scopes =
      typeof payload.scope === 'string' ? payload.scope.split(' ') : [];
    if (!clientAllowed || !scopes.includes(scope)) {
      return { status: 403, reason: 'unknown_client' };
    }

    return {
      taskId: binding.taskId,
      context: {
        tenant: { id: known.tenantId, slug: known.tenantSlug },
        agent: { id: agent.id, slug: agent.slug, identifier: agent.identifier },
      },
    };
  }

  /** Best effort: an audit failure never changes the refusal. */
  private async recordRejection(
    tenantSlug: string,
    agentSlug: string,
    token: string,
    unverified: JWTPayload,
    reason: string,
  ): Promise<void> {
    try {
      const tenant = await this.control.tenant.findUnique({
        where: { slug: tenantSlug },
      });
      if (!tenant || tenant.status !== 'ACTIVE') return;
      const tenantClient = await this.tenants.getClient(tenant.id);
      await this.audit.recordSafely(tenantClient, tenant.id, {
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
}
