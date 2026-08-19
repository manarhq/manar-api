import { Injectable } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { ComplianceFrameworkNotFoundError } from './compliance.errors';

export interface ComplianceFrameworkSummary {
  id: string;
  name: string;
  version: string;
}

export type ComplianceMappingStatus =
  'MAPPED' | 'EVIDENCE_AVAILABLE' | 'PARTIALLY_IMPLEMENTED' | 'NOT_EVALUATED';

export interface ComplianceControlMappingSummary {
  status: ComplianceMappingStatus;
  evidenceDescription: string;
  evidenceReference: string | null;
  assessedAt: Date;
}

export interface ComplianceControlWithMapping {
  id: string;
  controlId: string;
  title: string;
  description: string;
  /**
   * `null` only if a `ComplianceControl` row somehow has no
   * `ComplianceMapping` — never true for anything this phase's own seed
   * migration writes (every seeded control gets exactly one mapping in the
   * same migration, see `prisma/tenant/migrations/20260819060732_add_compliance_mapping/migration.sql`),
   * but the schema itself doesn't forbid it (the FK is on `ComplianceMapping`,
   * not the reverse), so this stays honestly nullable rather than assumed.
   */
  mapping: ComplianceControlMappingSummary | null;
}

/**
 * Phase 15a (Section 55) — read-only lookups against the seeded compliance-
 * control reference data (`ComplianceFramework`/`ComplianceControl`/
 * `ComplianceMapping`, `prisma/tenant.prisma`). There is no write surface
 * this phase: the mapping is a product-level, researched self-assessment
 * (see docs/compliance-mapping.md), not tenant-editable configuration —
 * seeded directly by this phase's own migration, identical for every
 * tenant.
 */
@Injectable()
export class ComplianceService {
  /** `GET /compliance/frameworks`. */
  async listFrameworks(
    tenantClient: TenantPrismaClient,
  ): Promise<ComplianceFrameworkSummary[]> {
    const rows = await tenantClient.complianceFramework.findMany({
      orderBy: { name: 'asc' },
    });
    return rows.map((row) => ({
      id: row.id,
      name: row.name,
      version: row.version,
    }));
  }

  /**
   * `GET /compliance/frameworks/:id/controls` — every control belonging to
   * `frameworkId`, each with its current mapping status/evidence.
   */
  async listControls(
    tenantClient: TenantPrismaClient,
    frameworkId: string,
  ): Promise<ComplianceControlWithMapping[]> {
    const framework = await tenantClient.complianceFramework.findUnique({
      where: { id: frameworkId },
    });
    if (!framework) throw new ComplianceFrameworkNotFoundError(frameworkId);

    const rows = await tenantClient.complianceControl.findMany({
      where: { frameworkId },
      orderBy: { controlId: 'asc' },
      include: { mapping: true },
    });

    return rows.map((row) => ({
      id: row.id,
      controlId: row.controlId,
      title: row.title,
      description: row.description,
      mapping: row.mapping
        ? {
            status: row.mapping.status,
            evidenceDescription: row.mapping.evidenceDescription,
            evidenceReference: row.mapping.evidenceReference,
            assessedAt: row.mapping.assessedAt,
          }
        : null,
    }));
  }
}
