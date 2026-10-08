import { Logger } from '@nestjs/common';
import { Command, CommandRunner, Option } from 'nest-commander';
import type {
  Prisma,
  PrismaClient as TenantPrismaClient,
} from '../../generated/tenant-client/client';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import {
  MANAR_ACTIONS,
  MANAR_BUILTIN_ENDPOINT,
  MANAR_TOOL,
} from '../../tools/manar-actions';

/**
 * ADR-0009: registers Manar's built-in connector (tool `manar` at `manar://builtin`)
 * and its catalog actions in one tenant. Idempotent. Rows are written from
 * the code catalog so policy and risk see the same flags the connector uses.
 */
export async function ensureManarConnector(
  tenantClient: TenantPrismaClient,
): Promise<{ id: string; name: string }> {
  const data = {
    type: 'MANAR',
    vendor: 'Manar',
    description:
      "Manar's own connector: read agent activity in this tenant, quarantine an agent. Restriction only; releasing a quarantine is a human action.",
    baseEndpoint: MANAR_BUILTIN_ENDPOINT,
    // See MANAR_BUILTIN_ENDPOINT for why this is not a protocol of its own.
    protocol: 'HTTP' as const,
    // Never resolved: the broker runs MANAR tools without a credential. The
    // column is required and validated, so it names an unused env variable.
    credentialReference: { provider: 'ENV', reference: 'MANAR_CONNECTOR_NONE' },
    metadata: { dataOrigin: 'MANAR' },
  };
  const tool = await tenantClient.tool.upsert({
    where: { name: MANAR_TOOL },
    create: { name: MANAR_TOOL, ...data },
    update: data,
  });
  for (const action of MANAR_ACTIONS) {
    const row = {
      description: action.description,
      riskBaseScore: action.riskBaseScore,
      mutating: action.mutating,
      destructive: action.destructive,
      inputSchema: action.inputSchema as Prisma.InputJsonObject,
    };
    await tenantClient.toolAction.upsert({
      where: { toolId_name: { toolId: tool.id, name: action.name } },
      create: { toolId: tool.id, name: action.name, ...row },
      update: row,
    });
  }
  return { id: tool.id, name: tool.name };
}

@Command({
  name: 'manar-connector:register',
  description:
    "Register Manar's built-in connector (manar.activity.read, manar.agent.quarantine) in one tenant",
})
export class ManarConnectorRegisterCommand extends CommandRunner {
  private readonly logger = new Logger(ManarConnectorRegisterCommand.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {
    super();
  }

  async run(_args: string[], options: { tenant: string }): Promise<void> {
    const tenant = await this.control.tenant.findUnique({
      where: { slug: options.tenant },
    });
    if (!tenant) throw new Error(`Tenant "${options.tenant}" not found`);
    const tool = await ensureManarConnector(
      await this.tenantDatabaseManager.getClient(tenant.id),
    );
    this.logger.log(`Registered tool "${tool.name}" (id=${tool.id})`);
    process.exitCode = 0;
  }

  @Option({
    flags: '--tenant <slug>',
    description: 'Tenant slug',
    required: true,
  })
  parseTenant(value: string): string {
    return value;
  }
}
