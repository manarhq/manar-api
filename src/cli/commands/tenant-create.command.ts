import { Logger } from '@nestjs/common';
import { Command, CommandRunner, Option } from 'nest-commander';
import { TenantProvisioningService } from '../../keycloak/tenant-provisioning.service';
import {
  TenantProvisioningError,
  TenantSlugConflictError,
} from '../../database/tenant-database.errors';

interface TenantCreateOptions {
  slug: string;
  name: string;
  residency: 'UAE' | 'CUSTOM_REGION' | 'AIR_GAPPED';
  allowExternalAi?: boolean;
  sector?: 'COMMERCIAL' | 'GOVERNMENT';
  allowOutboundTelemetry: boolean;
  allowCloudStorage: boolean;
}

const RESIDENCY_CHOICES = ['UAE', 'CUSTOM_REGION', 'AIR_GAPPED'] as const;

/**
 * `pnpm manar tenant:create --slug <s> --name <n> --residency <r>`
 *
 * This is the *only* way to create a tenant this phase (Section 11 — no
 * `/admin/all-tenants` HTTP endpoint, no application-level super admin, no
 * cross-tenant browsing surface at all). Provisions both the tenant's
 * isolated database (Phase 2) and its Keycloak realm/roles/client
 * (Phase 3) via `TenantProvisioningService`.
 */
@Command({
  name: 'tenant:create',
  description:
    'Provision a new tenant, its isolated database, and its Keycloak realm',
})
export class TenantCreateCommand extends CommandRunner {
  private readonly logger = new Logger(TenantCreateCommand.name);

  constructor(
    private readonly tenantProvisioningService: TenantProvisioningService,
  ) {
    super();
  }

  async run(
    _passedParams: string[],
    options: TenantCreateOptions,
  ): Promise<void> {
    try {
      const tenant = await this.tenantProvisioningService.provisionTenant({
        slug: options.slug,
        name: options.name,
        residency: options.residency,
        allowExternalAi: options.allowExternalAi,
        sector: options.sector,
        allowOutboundTelemetry: options.allowOutboundTelemetry,
        allowCloudStorage: options.allowCloudStorage,
      });

      this.logger.log(
        `Provisioned tenant "${tenant.slug}" (id=${tenant.id}, database=${tenant.databaseBinding?.databaseName}, keycloakRealm=${tenant.keycloakRealm})`,
      );
      process.exitCode = 0;
    } catch (error) {
      if (error instanceof TenantSlugConflictError) {
        this.logger.error(error.message);
        process.exitCode = 1;
        return;
      }
      if (error instanceof TenantProvisioningError) {
        this.logger.error(error.message);
        process.exitCode = 1;
        return;
      }
      throw error;
    }
  }

  @Option({
    flags: '-s, --slug <slug>',
    description: 'Unique, URL-safe tenant slug (e.g. "acme")',
    required: true,
  })
  parseSlug(value: string): string {
    return value;
  }

  @Option({
    flags: '-n, --name <name>',
    description: 'Human-readable tenant name',
    required: true,
  })
  parseName(value: string): string {
    return value;
  }

  @Option({
    flags: '-r, --residency <residency>',
    description: `Data residency posture (${RESIDENCY_CHOICES.join(' | ')})`,
    defaultValue: 'UAE',
    choices: [...RESIDENCY_CHOICES],
  })
  parseResidency(value: string): 'UAE' | 'CUSTOM_REGION' | 'AIR_GAPPED' {
    if (
      !RESIDENCY_CHOICES.includes(value as (typeof RESIDENCY_CHOICES)[number])
    ) {
      throw new Error(
        `Invalid --residency "${value}". Expected one of: ${RESIDENCY_CHOICES.join(', ')}`,
      );
    }
    return value as 'UAE' | 'CUSTOM_REGION' | 'AIR_GAPPED';
  }

  @Option({
    flags: '--allow-external-ai [boolean]',
    description:
      'Allow this tenant to use external AI providers (default: true only with --sector COMMERCIAL; otherwise false)',
  })
  parseAllowExternalAi(value: string): boolean {
    return parseBoolean(value);
  }

  @Option({
    flags: '--sector <sector>',
    description: 'COMMERCIAL or GOVERNMENT (Government: AI off)',
  })
  parseSector(value: string): 'COMMERCIAL' | 'GOVERNMENT' {
    const v = value.toUpperCase();
    if (v !== 'COMMERCIAL' && v !== 'GOVERNMENT')
      throw new Error(
        `Invalid --sector "${value}". Expected COMMERCIAL or GOVERNMENT`,
      );
    return v;
  }

  @Option({
    flags: '--allow-outbound-telemetry [boolean]',
    description:
      'Allow outbound telemetry for this tenant (default: false — safest)',
    defaultValue: false,
  })
  parseAllowOutboundTelemetry(value: string): boolean {
    return parseBoolean(value);
  }

  @Option({
    flags: '--allow-cloud-storage [boolean]',
    description:
      'Allow cloud storage for this tenant (default: false — safest)',
    defaultValue: false,
  })
  parseAllowCloudStorage(value: string): boolean {
    return parseBoolean(value);
  }
}

function parseBoolean(value: string): boolean {
  return value === undefined || value === '' ? true : value === 'true';
}
