import {
  Body,
  Controller,
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
import type { FastifyReply } from 'fastify';
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
  ) {}

  /**
   * Names the tenant's realm as the authorization server. Answers the same for
   * any agent slug of an active tenant, so it reveals nothing about which agents exist.
   */
  @Get('.well-known/oauth-protected-resource/mcp/:tenantSlug/:agentSlug')
  @Header('Cache-Control', 'public, max-age=300')
  async protectedResourceMetadata(
    @Param('tenantSlug') tenantSlug: string,
    @Param('agentSlug') agentSlug: string,
  ) {
    const host = cloudMcpSettings(this.config).host;
    if (!host || !SLUG.test(tenantSlug) || !SLUG.test(agentSlug)) {
      throw new NotFoundException();
    }
    const tenant = await failClosed('control-db', () =>
      this.control.tenant.findUnique({ where: { slug: tenantSlug } }),
    );
    if (!tenant || tenant.status !== 'ACTIVE' || !tenant.keycloakIssuerUrl) {
      throw new NotFoundException();
    }
    return {
      resource: cloudMcpResourceUrl(host, tenantSlug, agentSlug),
      authorization_servers: [tenant.keycloakIssuerUrl],
      scopes_supported: [cloudMcpScope(agentSlug)],
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
