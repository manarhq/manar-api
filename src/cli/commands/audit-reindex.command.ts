import { Logger } from '@nestjs/common';
import { Command, CommandRunner, Option } from 'nest-commander';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import { AuditReindexService } from '../../audit/opensearch/audit-reindex.service';

interface AuditReindexOptions {
  tenant: string;
}

/**
 * `pnpm manar audit:reindex --tenant <id>` (Phase 9b, Section 45). The
 * real disaster-recovery path for the OpenSearch audit-event index: reads
 * every `AuditEvent` for the named tenant straight from Postgres (the
 * authoritative store) and upserts each into OpenSearch, exactly as if the
 * index had never existed. Idempotent — safe to run against an index that
 * already has some or all of these events indexed (upsert by `eventId`,
 * Section 29).
 */
@Command({
  name: 'audit:reindex',
  description:
    'Fully reconstruct one tenant’s OpenSearch audit-event index from Postgres',
})
export class AuditReindexCommand extends CommandRunner {
  private readonly logger = new Logger(AuditReindexCommand.name);

  constructor(
    private readonly tenantDatabaseManager: TenantDatabaseManager,
    private readonly auditReindexService: AuditReindexService,
  ) {
    super();
  }

  async run(
    _passedParams: string[],
    options: AuditReindexOptions,
  ): Promise<void> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      options.tenant,
    );
    const { count } = await this.auditReindexService.reindexTenant(
      tenantClient,
      options.tenant,
    );
    this.logger.log(
      `Reindexed ${count} AuditEvent row(s) for tenant "${options.tenant}"`,
    );
    process.exitCode = 0;
  }

  @Option({
    flags: '-t, --tenant <tenant>',
    description: 'Tenant id whose AuditEvent chain should be reindexed',
    required: true,
  })
  parseTenant(value: string): string {
    return value;
  }
}
