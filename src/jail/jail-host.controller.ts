import {
  BadRequestException,
  Body,
  Controller,
  ForbiddenException,
  HttpCode,
  Post,
  UseGuards,
} from '@nestjs/common';
import { ApiExcludeController } from '@nestjs/swagger';
import { z } from 'zod';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { HostApprovalsService } from '../approvals/host-approvals.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { HostAuthGuard } from '../host-mtls/host-auth.guard';
import { CurrentHost, type HostContext } from '../host-mtls/host-context';
import {
  isJailTool,
  JAIL_TOOL_NAMES,
  jailFlags,
  normalizeAskedSite,
  SITE_CONNECT_ACTION,
} from './jail-sites';
import { JailSitesService } from './jail-sites.service';

export const JailAskSchema = z.object({
  toolId: z.string().min(1).max(128),
  site: z.string().min(1).max(260),
});

/**
 * `POST /host/v1/jail/ask`: a protected tool reached for a site that is not allowed yet. A remembered
 * answer comes straight back; otherwise a WARDEN prompt is opened (a `HostApproval` with action
 * `site.connect`) that the device polls through `/host/v1/approvals/:id`. Tenant and host come from
 * the certificate; the body cannot name another device.
 */
@ApiExcludeController()
@Controller('host/v1/jail')
@UseGuards(HostAuthGuard)
export class JailHostController {
  constructor(
    private readonly sites: JailSitesService,
    private readonly approvals: HostApprovalsService,
    private readonly tenants: TenantDatabaseManager,
  ) {}

  @Post('ask')
  @HttpCode(200)
  async ask(@CurrentHost() host: HostContext, @Body() body: unknown) {
    const input = parseBodyOrThrow(JailAskSchema, body);
    if (host.status !== 'APPROVED')
      throw new ForbiddenException('device_not_approved');
    if (!jailFlags().enabled) throw new ForbiddenException('jail_off');
    if (!isJailTool(input.toolId))
      throw new BadRequestException('this tool is not filtered');
    const site = normalizeAskedSite(input.site);
    if (!site) throw new BadRequestException('not a valid site');
    const client = await this.tenants.getClient(host.tenantId);
    const rule = await this.sites.findLive(
      client,
      host.hostId,
      input.toolId,
      site,
    );
    if (rule)
      return { decision: rule.mode === 'ALLOW' ? 'allow' : ('deny' as const) };
    const toolName = JAIL_TOOL_NAMES[input.toolId] ?? input.toolId;
    const row = await this.approvals.open(client, host.tenantId, {
      hostId: host.hostId,
      toolId: input.toolId,
      actionId: SITE_CONNECT_ACTION,
      resource: site,
      summary: `${toolName} wants to connect to ${site}`,
      highRisk: false,
      toolName,
    });
    return { decision: 'ask' as const, id: row.id, expiresAt: row.expiresAt };
  }
}
