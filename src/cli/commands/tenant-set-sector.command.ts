import { Logger } from '@nestjs/common';
import { Command, CommandRunner } from 'nest-commander';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { TenantSectorService } from '../../tenant-settings/tenant-sector.service';

/**
 * `pnpm manar tenant:set-sector <slug> COMMERCIAL|GOVERNMENT`: records the sector of a legacy
 * workspace that has none. Audited in the tenant's own log; prints no identifiers.
 */
@Command({
  name: 'tenant:set-sector',
  description: 'Record a workspace sector (COMMERCIAL or GOVERNMENT)',
  arguments: '<slug> <sector>',
})
export class TenantSetSectorCommand extends CommandRunner {
  private readonly logger = new Logger(TenantSetSectorCommand.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly sectors: TenantSectorService,
  ) {
    super();
  }

  async run(params: string[]): Promise<void> {
    const [slug, raw] = params;
    const sector = raw?.toUpperCase();
    if (!slug || (sector !== 'COMMERCIAL' && sector !== 'GOVERNMENT')) {
      this.logger.error(
        'Usage: tenant:set-sector <slug> COMMERCIAL|GOVERNMENT',
      );
      process.exitCode = 2;
      return;
    }
    const tenant = await this.control.tenant.findUnique({ where: { slug } });
    if (!tenant || tenant.status !== 'ACTIVE') {
      this.logger.error('No ACTIVE workspace with that slug');
      process.exitCode = 1;
      return;
    }
    await this.sectors.set(tenant.id, sector, 'cli:tenant:set-sector');
    this.logger.log(`Sector set to ${sector}`);
  }
}
