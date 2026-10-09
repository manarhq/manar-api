import { Logger } from '@nestjs/common';
import { Command, CommandRunner, Option } from 'nest-commander';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import { syncMicrosoftActions } from './microsoft-fixture-seed';

const ENDPOINTS = {
  graph: { baseEndpoint: 'https://graph.microsoft.com/v1.0', type: 'IAM' },
  defender: {
    baseEndpoint: 'https://api.securitycenter.microsoft.com/api',
    type: 'EDR',
  },
} as const;

interface Options {
  tenant: string;
  name: string;
  api: 'graph' | 'defender';
  azureTenant: string;
  clientId: string;
  kvPath: string;
}

/**
 * ADR-0004 §9: registers (or updates) a Microsoft tool on a customer's live
 * tenant and writes its `ToolAction` rows from the code catalog, so a new
 * catalog action reaches policy, risk and the tool manifest. The client
 * secret is not an option: it must already be in OpenBao at `--kv-path`.
 * Prints ids only.
 */
@Command({
  name: 'microsoft:register',
  description:
    'Register or update a live Microsoft Graph/Defender tool in one tenant and sync its actions from the catalog',
})
export class MicrosoftRegisterCommand extends CommandRunner {
  private readonly logger = new Logger(MicrosoftRegisterCommand.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {
    super();
  }

  async run(_args: string[], options: Options): Promise<void> {
    const tenant = await this.control.tenant.findUnique({
      where: { slug: options.tenant },
    });
    if (!tenant) throw new Error(`Tenant "${options.tenant}" not found`);
    const client = await this.tenantDatabaseManager.getClient(tenant.id);
    const endpoint = ENDPOINTS[options.api];
    const data = {
      type: endpoint.type,
      vendor: 'Microsoft',
      description: `Microsoft ${options.api === 'graph' ? 'Graph' : 'Defender for Endpoint'} connector on a live tenant.`,
      baseEndpoint: endpoint.baseEndpoint,
      protocol: 'MICROSOFT' as const,
      credentialReference: { provider: 'OPENBAO', reference: options.kvPath },
      metadata: {
        api: options.api,
        azureTenantId: options.azureTenant,
        clientId: options.clientId,
        dataOrigin: 'LIVE',
      },
    };
    const tool = await client.tool.upsert({
      where: { name: options.name },
      create: { name: options.name, ...data },
      update: data,
    });
    const count = await syncMicrosoftActions(client, tool.id, options.api);
    this.logger.log(
      `Tool "${tool.name}" (id=${tool.id}) registered with ${count} actions`,
    );
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

  @Option({ flags: '--name <tool>', description: 'Tool name', required: true })
  parseName(value: string): string {
    return value;
  }

  @Option({
    flags: '--api <api>',
    description: 'graph or defender',
    defaultValue: 'graph',
  })
  parseApi(value: string): 'graph' | 'defender' {
    if (value !== 'graph' && value !== 'defender') {
      throw new Error('--api must be graph or defender');
    }
    return value;
  }

  @Option({
    flags: '--azure-tenant <id>',
    description: 'Entra tenant id',
    required: true,
  })
  parseAzureTenant(value: string): string {
    return value;
  }

  @Option({
    flags: '--client-id <id>',
    description: 'App registration (client) id',
    required: true,
  })
  parseClientId(value: string): string {
    return value;
  }

  @Option({
    flags: '--kv-path <path>',
    description: 'OpenBao KV path holding the client secret',
    required: true,
  })
  parseKvPath(value: string): string {
    return value;
  }
}
