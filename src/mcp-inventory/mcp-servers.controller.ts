import { Controller, Get, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { listMcpServers } from './mcp-inventory';

/** The MCP servers page: what each protected tool is configured to use, with deterministic flags. */
@ApiTags('mcp-servers')
@ApiBearerAuth('jwt')
@Controller('mcp-servers')
@UseGuards(JwtAuthGuard, RolesGuard)
export class McpServersController {
  constructor(private readonly tenants: TenantDatabaseManager) {}

  @Get()
  @RequireRole('AUDITOR', 'SECURITY_ADMIN', 'TENANT_OWNER')
  @ApiOperation({
    summary: 'MCP servers found on the workspace devices, with risk flags',
    description:
      'Flags: unknown_publisher, unpinned_version, remote_no_tls, runs_shell, writes_outside_home. No flags means nothing was found, not that the server is safe. Env values and secret-looking arguments never leave the device; only variable names are kept.',
  })
  async list(@CurrentAuth() auth: AuthContext) {
    return listMcpServers(await this.tenants.getClient(auth.tenant.id));
  }
}
