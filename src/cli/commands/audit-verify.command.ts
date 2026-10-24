import { Logger } from '@nestjs/common';
import { Command, CommandRunner, Option } from 'nest-commander';
import { AuditService } from '../../audit/audit.service';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';

interface AuditVerifyOptions {
  tenant?: string;
}

/**
 * `pnpm manar audit:verify [--tenant <id>]`: walks every active tenant's
 * audit hash chain (the same check as `GET /audit/verify`) and exits 1 if
 * any chain is broken. Used by the restore drill to prove a restored
 * database still holds verifiable evidence; needs only PostgreSQL and the
 * tenant database credentials, never Kafka or the HTTP app.
 */
@Command({
  name: 'audit:verify',
  description:
    "Verify every active tenant's audit hash chain (exit 1 if any is broken)",
})
export class AuditVerifyCommand extends CommandRunner {
  private readonly logger = new Logger(AuditVerifyCommand.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
    private readonly auditService: AuditService,
  ) {
    super();
  }

  async run(_params: string[], options: AuditVerifyOptions): Promise<void> {
    const tenants = await this.control.tenant.findMany({
      where: {
        status: 'ACTIVE',
        databaseBinding: { provisioningStatus: 'ACTIVE' },
        ...(options.tenant ? { id: options.tenant } : {}),
      },
      select: { id: true },
      orderBy: { createdAt: 'asc' },
    });
    let broken = 0;
    for (const { id } of tenants) {
      const client = await this.tenantDatabaseManager.getClient(id);
      const events = await client.auditEvent.count();
      const result = await this.auditService.verifyAuditChain(client);
      if (result.valid) {
        this.logger.log(`tenant ${id}: chain valid (${events} events)`);
      } else {
        broken += 1;
        this.logger.error(
          `tenant ${id}: chain BROKEN at ${result.brokenAt} (${events} events)`,
        );
      }
    }
    this.logger.log(
      `Verified ${tenants.length} tenant chain(s), ${broken} broken`,
    );
    process.exitCode = broken === 0 && tenants.length > 0 ? 0 : 1;
  }

  @Option({
    flags: '-t, --tenant <tenant>',
    description: 'Only this tenant id',
  })
  parseTenant(value: string): string {
    return value;
  }
}
