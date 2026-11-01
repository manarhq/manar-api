import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Put,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import {
  BindTaskSchema,
  CloudAgentsService,
  ConfirmClientSchema,
  ConnectCloudAgentSchema,
  DisconnectSchema,
  EntraIdpSchema,
  RedirectUrisSchema,
} from './cloud-agents.service';

/** "Connect a cloud agent" (docs/cloud-agents.md): tenant admins only. */
@ApiTags('cloud-agents')
@ApiBearerAuth('jwt')
@Controller('cloud-agents')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('SECURITY_ADMIN', 'TENANT_OWNER')
export class CloudAgentsController {
  constructor(private readonly cloudAgents: CloudAgentsService) {}

  @Post()
  @ApiOperation({
    summary: 'Connect a cloud agent (Copilot Studio or ChatGPT)',
    description:
      'Creates an ACTIVE agent of kind CLOUD with its standing task (`task`, same fields as `POST /tasks`) and the OAuth set-up in the tenant realm, including the realm role `manar-agent-<slug>` people need (assign it, or name an Entra group in `entraGroupId`). A connection that failed part way is resumed by calling again with the same slug. Returns what to paste into the vendor: MCP URL, authorization and token URLs, scope and, for Copilot Studio, a client id and a client secret shown only in this response. 400 `cloud_mcp_not_enabled` when the install has no public MCP endpoint.',
  })
  @ApiResponse({ status: 201 })
  @ApiResponse({ status: 400 })
  @ApiResponse({
    status: 409,
    description: 'Slug taken or tenant has no realm.',
  })
  connect(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    return this.cloudAgents.connect(
      auth,
      parseBodyOrThrow(ConnectCloudAgentSchema, body),
    );
  }

  @Get()
  @ApiOperation({
    summary: 'The tenant cloud agents',
    description:
      'Each agent with its platform, MCP URL, `paused` (over the plan cap after a downgrade: nothing is deleted, it resumes when under the cap) and any client waiting for confirmation, plus `limit` `{ max, used }`.',
  })
  list(@CurrentAuth() auth: AuthContext) {
    return this.cloudAgents.list(auth);
  }

  @Put(':id/redirect-uris')
  @ApiOperation({
    summary: "Set a Copilot Studio agent's OAuth callback URL(s)",
    description:
      'https URLs, no wildcards. Replaces the list on the Keycloak client.',
  })
  @ApiParam({ name: 'id', description: 'Agent ID', format: 'uuid' })
  setRedirectUris(
    @CurrentAuth() auth: AuthContext,
    @Param('id') agentId: string,
    @Body() body: unknown,
  ) {
    const { redirectUris } = parseBodyOrThrow(RedirectUrisSchema, body);
    return this.cloudAgents.setRedirectUris(auth, agentId, redirectUris);
  }

  @Put(':id/task')
  @ApiOperation({
    summary: "Replace a cloud agent's standing task",
    description:
      'The task must be ACTIVE and assigned to this agent (create it with `POST /tasks`).',
  })
  @ApiParam({ name: 'id', description: 'Agent ID', format: 'uuid' })
  bindTask(
    @CurrentAuth() auth: AuthContext,
    @Param('id') agentId: string,
    @Body() body: unknown,
  ) {
    return this.cloudAgents.bindTask(
      auth,
      agentId,
      parseBodyOrThrow(BindTaskSchema, body).taskId,
    );
  }

  @Put('entra-identity-provider')
  @RequireRole('TENANT_OWNER')
  @ApiOperation({
    summary: "Broker the tenant's Entra ID in its Keycloak realm",
    description:
      'Creates or updates the `entra` OIDC identity provider (single Entra directory). The client secret goes to Keycloak only. Returns the redirect URI to register on the Entra app registration. TENANT_OWNER only.',
  })
  configureEntra(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    return this.cloudAgents.configureEntra(
      auth,
      parseBodyOrThrow(EntraIdpSchema, body),
    );
  }

  @Get(':id')
  @ApiOperation({
    summary: 'A cloud agent binding',
    description:
      'Platform, standing task, confirmed client and, for ChatGPT, the self-registered client waiting for confirmation (registration time, redirect URIs, grants).',
  })
  @ApiParam({ name: 'id', description: 'Agent ID', format: 'uuid' })
  describe(@CurrentAuth() auth: AuthContext, @Param('id') agentId: string) {
    return this.cloudAgents.describe(auth, agentId);
  }

  @Post(':id/oauth-client/confirm')
  @ApiOperation({
    summary: 'Confirm the client a ChatGPT agent registered',
    description:
      'Body `{ clientId }`, which must be the waiting client. Until confirmed, its calls get 403 `cloud_client_pending_approval`. Keycloak then requires PKCE S256 from it.',
  })
  @ApiParam({ name: 'id', description: 'Agent ID', format: 'uuid' })
  confirmClient(
    @CurrentAuth() auth: AuthContext,
    @Param('id') agentId: string,
    @Body() body: unknown,
  ) {
    return this.cloudAgents.confirmDcrClient(
      auth,
      agentId,
      parseBodyOrThrow(ConfirmClientSchema, body).clientId,
    );
  }

  @Delete(':id/oauth-client')
  @ApiOperation({
    summary: 'Reject or forget the client a ChatGPT agent registered',
    description:
      'Rejects the waiting client or forgets the confirmed one, and deletes every self-registered client carrying this agent scope; the connector must register again and wait for confirmation.',
  })
  @ApiParam({ name: 'id', description: 'Agent ID', format: 'uuid' })
  resetDcrClient(
    @CurrentAuth() auth: AuthContext,
    @Param('id') agentId: string,
  ) {
    return this.cloudAgents.resetDcrClient(auth, agentId);
  }

  @Delete(':id')
  @ApiOperation({
    summary: 'Disconnect (revoke) a cloud agent',
    description:
      'Revokes the agent and its standing task, then removes its Keycloak client, scope, role, Entra mapper and DCR policy entry (DCR closes when no ChatGPT agent is left). Body `{ reason }`. Repeatable if Keycloak fails part way. Cloud agents are not revoked with `POST /agents/:id/revoke`.',
  })
  @ApiParam({ name: 'id', description: 'Agent ID', format: 'uuid' })
  disconnect(
    @CurrentAuth() auth: AuthContext,
    @Param('id') agentId: string,
    @Body() body: unknown,
  ) {
    return this.cloudAgents.disconnect(
      auth,
      agentId,
      parseBodyOrThrow(DisconnectSchema, body).reason,
    );
  }
}
