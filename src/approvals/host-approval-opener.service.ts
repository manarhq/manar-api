import { Injectable } from '@nestjs/common';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import type {
  HostApprovalOpener,
  HostAuthorizeRequest,
} from '../host-coverage/host-authorize.service';
import type { HostContext } from '../host-mtls/host-context';
import { HostApprovalsService } from './host-approvals.service';

/** Catalogue risk (10 + base + 15 mutating + 25 destructive) from which only the console may decide. */
export const HIGH_RISK_SCORE = 50;

const NAMES: Record<string, string> = {
  'host.claude-code': 'Claude Code',
  'host.claude-desktop': 'Claude Desktop',
  'host.cursor': 'Cursor',
  'host.windsurf': 'Windsurf',
  'host.vscode-copilot': 'VS Code Copilot',
  'host.copilot-cli': 'Copilot CLI',
  'host.codex-cli': 'Codex CLI',
  'host.chatgpt-desktop': 'ChatGPT Desktop',
  'host.gemini-cli': 'Gemini CLI',
};

@Injectable()
export class HostApprovalOpenerService implements HostApprovalOpener {
  constructor(
    private readonly tenants: TenantDatabaseManager,
    private readonly approvals: HostApprovalsService,
  ) {}

  async open(
    host: HostContext,
    request: HostAuthorizeRequest,
    decision: { reason: string; riskScore: number; askKey?: string },
  ) {
    // Tenant and host come from the verified certificate, never from the request body.
    const client = await this.tenants.getClient(host.tenantId);
    const toolName = NAMES[request.toolId] ?? request.toolId;
    const row = await this.approvals.open(client, host.tenantId, {
      hostId: host.hostId,
      toolId: request.toolId,
      // The same lower-casing the authorize path uses, so an 8-hour grant matches the next call.
      actionId: request.actionId.toLowerCase(),
      resource: request.resource,
      summary: `${toolName}: ${request.actionId}`,
      highRisk: decision.riskScore >= HIGH_RISK_SCORE,
      toolName,
      askKey: decision.askKey,
    });
    return { id: row.id, expiresAt: row.expiresAt };
  }
}
