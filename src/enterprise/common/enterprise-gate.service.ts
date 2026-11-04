import { Injectable, NotFoundException } from '@nestjs/common';
import { failClosed } from '../../common/fail-closed/fail-closed';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { CatalogService } from '../../platform/catalog.service';

export interface EnterpriseTenant {
  tenantId: string;
  sector: 'ENTERPRISE' | 'GOVERNMENT';
  publicSlug: string;
}

/**
 * The one switch for enterprise mode. A tenant is in it only when it is ACTIVE, its catalog flag
 * `enterprise` is on (default off) and it has an `enterprise_profiles` row. Off is 404 (the surface
 * does not exist for that tenant); a failure to read any of the three is 503, never "on".
 */
@Injectable()
export class EnterpriseGateService {
  constructor(
    private readonly control: ControlPrismaService,
    private readonly catalog: CatalogService,
  ) {}

  requireEnabled(tenantId: string): Promise<EnterpriseTenant> {
    return failClosed('enterprise-gate', async () => {
      const tenant = await this.control.tenant.findUnique({
        where: { id: tenantId },
        select: { status: true },
      });
      if (tenant?.status !== 'ACTIVE') throw new NotFoundException();
      const state = await this.catalog.state(tenantId);
      if (state.features.enterprise !== true) throw new NotFoundException();
      const p = await this.control.enterpriseProfile.findUnique({
        where: { tenantId },
      });
      if (!p) throw new NotFoundException();
      return { tenantId, sector: p.sector, publicSlug: p.publicSlug };
    });
  }
}
