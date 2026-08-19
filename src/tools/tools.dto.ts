import { ApiProperty } from '@nestjs/swagger';

/** One `ToolAction` row, embedded in `ToolSummaryDto.actions` — see `ToolRegistryService.list`. */
export class ToolActionSummaryDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({ format: 'uuid' })
  toolId!: string;

  @ApiProperty({ example: 'isolate_host' })
  name!: string;

  @ApiProperty({ nullable: true })
  description!: string | null;

  @ApiProperty({ minimum: 0, maximum: 100 })
  riskBaseScore!: number;

  @ApiProperty()
  mutating!: boolean;

  @ApiProperty()
  destructive!: boolean;

  @ApiProperty()
  approvalDefault!: boolean;

  @ApiProperty({
    enum: ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED'],
    description:
      'Phase 15a (Section 53) data-sensitivity tag — see docs/data-classification.md. Defaults to INTERNAL.',
  })
  classification!: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
}

/**
 * One row of `GET /tools`'s paginated list — see
 * `ToolRegistryService.list`. Deliberately excludes `credentialReference`
 * (never exposed over this HTTP surface, even as a pointer — see that
 * method's doc comment).
 */
export class ToolSummaryDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({ example: 'edr' })
  name!: string;

  @ApiProperty({ example: 'EDR' })
  type!: string;

  @ApiProperty({ nullable: true })
  vendor!: string | null;

  @ApiProperty({ nullable: true })
  description!: string | null;

  @ApiProperty()
  baseEndpoint!: string;

  @ApiProperty({ enum: ['HTTP', 'MCP'] })
  protocol!: 'HTTP' | 'MCP';

  @ApiProperty()
  enabled!: boolean;

  @ApiProperty({ type: () => ToolActionSummaryDto, isArray: true })
  actions!: ToolActionSummaryDto[];

  @ApiProperty({ format: 'date-time' })
  createdAt!: Date;
}

/** `GET /tools`'s response envelope — see `AgentListResponseDto`'s identical shape/doc comment. */
export class ToolListResponseDto {
  @ApiProperty({ type: () => ToolSummaryDto, isArray: true })
  items!: ToolSummaryDto[];

  @ApiProperty({ nullable: true })
  nextCursor!: string | null;
}
