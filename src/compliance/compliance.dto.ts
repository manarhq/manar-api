import { ApiProperty } from '@nestjs/swagger';

/** One row of `GET /compliance/frameworks` — see `ComplianceService.listFrameworks`. */
export class ComplianceFrameworkSummaryDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({ example: 'ISO/IEC 27001' })
  name!: string;

  @ApiProperty({ example: '2022' })
  version!: string;
}

/** `GET /compliance/frameworks`'s response envelope. */
export class ComplianceFrameworkListResponseDto {
  @ApiProperty({ type: () => ComplianceFrameworkSummaryDto, isArray: true })
  items!: ComplianceFrameworkSummaryDto[];
}

/**
 * This codebase's own honest self-assessment against one control — see
 * `ComplianceMappingStatus` (`prisma/tenant.prisma`) and
 * docs/compliance-mapping.md for the four allowed statuses and the
 * methodology. **Never implies certification** — `MAPPED` means "this
 * capability is built and evidenced," not "an external auditor has
 * certified this."
 */
export class ComplianceMappingSummaryDto {
  @ApiProperty({
    enum: [
      'MAPPED',
      'EVIDENCE_AVAILABLE',
      'PARTIALLY_IMPLEMENTED',
      'NOT_EVALUATED',
    ],
  })
  status!:
    'MAPPED' | 'EVIDENCE_AVAILABLE' | 'PARTIALLY_IMPLEMENTED' | 'NOT_EVALUATED';

  @ApiProperty({
    description:
      'Free text pointing at real, specific capabilities this codebase has built and tested — never fabricated.',
  })
  evidenceDescription!: string;

  @ApiProperty({ nullable: true, example: 'docs/audit-chain.md' })
  evidenceReference!: string | null;

  @ApiProperty({ format: 'date-time' })
  assessedAt!: Date;
}

/** One row of `GET /compliance/frameworks/:id/controls` — see `ComplianceService.listControls`. */
export class ComplianceControlWithMappingDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({
    example: 'A.5.15',
    description: "The framework's own control numbering.",
  })
  controlId!: string;

  @ApiProperty({ example: 'Access control' })
  title!: string;

  @ApiProperty()
  description!: string;

  @ApiProperty({
    type: () => ComplianceMappingSummaryDto,
    nullable: true,
    description:
      "Always present for this phase's seeded controls; nullable only because the schema does not structurally forbid a control with no mapping.",
  })
  mapping!: ComplianceMappingSummaryDto | null;
}

/** `GET /compliance/frameworks/:id/controls`'s response envelope. */
export class ComplianceControlListResponseDto {
  @ApiProperty({ type: () => ComplianceControlWithMappingDto, isArray: true })
  items!: ComplianceControlWithMappingDto[];
}
