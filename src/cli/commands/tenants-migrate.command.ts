import { Logger } from '@nestjs/common';
import { Command, CommandRunner } from 'nest-commander';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';

/**
 * `pnpm manar tenants:migrate`: applies pending tenant-schema migrations to
 * every ACTIVE tenant database (bounded concurrency, continues past a failed tenant and exits 1 if any failed). Part of every upgrade, after
 * `db:migrate:control:deploy` and before the new API version takes traffic.
 * Idempotent (`prisma migrate deploy`).
 */
@Command({
  name: 'tenants:migrate',
  description: 'Apply pending tenant-schema migrations to every active tenant',
})
export class TenantsMigrateCommand extends CommandRunner {
  private readonly logger = new Logger(TenantsMigrateCommand.name);

  constructor(private readonly tenantDatabaseManager: TenantDatabaseManager) {
    super();
  }

  async run(): Promise<void> {
    const { migrated, failed } =
      await this.tenantDatabaseManager.migrateAllTenants();
    this.logger.log(`Migrated ${migrated.length} tenant database(s)`);
    for (const f of failed) {
      this.logger.error(`FAILED ${f.slug} (${f.tenantId}): ${f.error}`);
    }
    // Every tenant was attempted; a non-zero exit still stops the deploy from taking traffic.
    process.exitCode = failed.length > 0 ? 1 : 0;
  }
}
