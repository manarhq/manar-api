import { Logger } from '@nestjs/common';
import { Command, CommandRunner } from 'nest-commander';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';

/**
 * `pnpm manar tenants:migrate`: applies pending tenant-schema migrations to
 * every ACTIVE tenant database. Part of every upgrade, after
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
    const migrated = await this.tenantDatabaseManager.migrateAllTenants();
    this.logger.log(`Migrated ${migrated.length} tenant database(s)`);
    process.exitCode = 0;
  }
}
