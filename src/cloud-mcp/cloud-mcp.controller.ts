import {
  Body,
  Controller,
  HttpException,
  HttpStatus,
  Delete,
  Get,
  Header,
  NotFoundException,
  Param,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ApiExcludeController } from '@nestjs/swagger';
import { InjectThrottlerStorage } from '@nestjs/throttler';
import type { ThrottlerStorage } from '@nestjs/throttler';
import type { FastifyReply, FastifyRequest } from 'fastify';
import {
  AgentRuntimeController,
  methodNotAllowed,
} from '../agent-runtime/agent-runtime.controller';
import { failClosed } from '../common/fail-closed/fail-closed';
import type { AppConfig } from '../config/env.validation';
import { ControlPrismaService } from '../database/control-prisma.service';
import { CloudMcpAuthGuard } from './cloud-mcp-auth.guard';
import type { CloudMcpRequest } from './cloud-mcp-auth.guard';
import {
  cloudMcpResourceUrl,
  cloudMcpScope,
  cloudMcpSettings,
} from './cloud-mcp.config';

const SLUG = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
/** Metadata requests per caller address per minute. */
const METADATA_PER_ADDRESS = 120;
const ISSUER_CACHE_MS = 60_000;

interface ResourceRealm {
  issuer: string;
  /** Set when the tenant is on the shared realm: its scope names carry the tenant id. */
  sharedTenantId?: string;
}

/**
 * The public MCP endpoint for cloud agents (docs/cloud-agents.md), on the
 * HTTP app and meant for the `MANAR_MCP_HOST` ingress: RFC 9728 protected
 * resource metadata per agent, and the same governed MCP server the mTLS
 * listener serves (`AgentRuntimeController.serveMcp`), run for the agent and
 * standing task `CloudMcpAuthGuard` resolved from the token. Not part of the
 * human OpenAPI document.
 */
@ApiExcludeController()
@Controller()
export class CloudMcpController {
  constructor(
    private readonly config: ConfigService<AppConfig, true>,
    private readonly control: ControlPrismaService,
    private readonly runtime: AgentRuntimeController,
    @InjectThrottlerStorage() private readonly limits: ThrottlerStorage,
  ) {}

  // ponytail: per-process cache of active tenants' issuers, one minute; a suspended tenant's
  // metadata can outlive the suspension by that long (tokens are still refused by the guard).
  private readonly issuers = new Map<
    string,
    { found: ResourceRealm | null; until: number }
  >();

  /** The authorization server for a tenant, and the tenant id when it is the shared realm. */
  private async issuerOf(tenantSlug: string): Promise<ResourceRealm | null> {
    const cached = this.issuers.get(tenantSlug);
    if (cached && cached.until > Date.now()) return cached.found;
    const tenant = await failClosed('control-db', () =>
      this.control.tenant.findUnique({ where: { slug: tenantSlug } }),
    );
    const shared = cloudMcpSettings(this.config).sharedIssuer;
    const found: ResourceRealm | null =
      tenant?.status !== 'ACTIVE'
        ? null
        : tenant.keycloakIssuerUrl
          ? { issuer: tenant.keycloakIssuerUrl }
          : shared
            ? { issuer: shared, sharedTenantId: tenant.id }
            : null;
    if (this.issuers.size > 10_000) this.issuers.clear();
    this.issuers.set(tenantSlug, {
      found,
      until: Date.now() + ISSUER_CACHE_MS,
    });
    return found;
  }

  /**
   * Names the tenant's realm as the authorization server. Answers the same for
   * any agent slug of an active tenant, so it reveals nothing about which agents exist.
   */
  @Get('.well-known/oauth-protected-resource/mcp/:tenantSlug/:agentSlug')
  @Header('Cache-Control', 'public, max-age=300')
  async protectedResourceMetadata(
    @Param('tenantSlug') tenantSlug: string,
    @Param('agentSlug') agentSlug: string,
    @Req() request: FastifyRequest,
  ) {
    const host = cloudMcpSettings(this.config).host;
    if (!host || !SLUG.test(tenantSlug) || !SLUG.test(agentSlug)) {
      throw new NotFoundException();
    }
    const usage = await failClosed('rate-limit-store', () =>
      this.limits.increment(
        `cloud-mcp-meta:${request.ip}`,
        60_000,
        METADATA_PER_ADDRESS,
        60_000,
        'cloud-mcp',
      ),
    );
    if (usage.isBlocked) {
      throw new HttpException(
        { statusCode: 429, reason: 'rate_limited' },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
    const realm = await this.issuerOf(tenantSlug);
    if (!realm) throw new NotFoundException();
    return {
      resource: cloudMcpResourceUrl(host, tenantSlug, agentSlug),
      authorization_servers: [realm.issuer],
      scopes_supported: [cloudMcpScope(agentSlug, realm.sharedTenantId)],
      bearer_methods_supported: ['header'],
      resource_name: 'Manar governed tools',
    };
  }

  @Post('mcp/:tenantSlug/:agentSlug')
  @UseGuards(CloudMcpAuthGuard)
  async mcp(
    @Req() request: CloudMcpRequest,
    @Body() body: unknown,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const { context, taskId } = request.cloudAgent!;
    await this.runtime.serveMcp(context, taskId, body, request, reply);
  }

  /** Stateless server, as on the mTLS listener: no SSE stream, no sessions. */
  @Get('mcp/:tenantSlug/:agentSlug')
  @UseGuards(CloudMcpAuthGuard)
  mcpGet(@Res() reply: FastifyReply): void {
    methodNotAllowed(reply);
  }

  @Delete('mcp/:tenantSlug/:agentSlug')
  @UseGuards(CloudMcpAuthGuard)
  mcpDelete(@Res() reply: FastifyReply): void {
    methodNotAllowed(reply);
  }
}
