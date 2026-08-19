import { ApiProperty } from '@nestjs/swagger';

/** Mirrors `VerifyAuditChainResult` (`audit.service.ts`) — a discriminated union collapsed into one optional-field shape for Swagger (which cannot express a TS discriminated union directly without oneOf/discriminator wiring this phase doesn't need). */
export class VerifyAuditChainResponseDto {
  @ApiProperty({
    description:
      "True iff every event's hash and chain linkage verified correctly.",
  })
  valid!: boolean;

  @ApiProperty({
    required: false,
    format: 'uuid',
    description:
      'Present only when valid=false: the AuditEvent.id where verification first failed.',
  })
  brokenAt?: string;
}

/**
 * One row of `GET /audit`'s search results — mirrors
 * `AuditEventDocument` (`opensearch/opensearch-client.service.ts`), the
 * OpenSearch-indexed shape, not the raw Postgres `AuditEvent` row.
 */
export class AuditEventSearchResultDto {
  @ApiProperty({ format: 'uuid' })
  eventId!: string;

  @ApiProperty({ format: 'uuid' })
  tenantId!: string;

  @ApiProperty()
  sequence!: number;

  @ApiProperty({ example: 'tool.invocation.completed' })
  eventType!: string;

  @ApiProperty({ format: 'uuid' })
  correlationId!: string;

  @ApiProperty({
    description: '`{ type: "human"|"agent"|"system", id }` — see `AuditActor`.',
  })
  actor!: unknown;

  @ApiProperty({ format: 'date-time' })
  timestamp!: string;

  @ApiProperty({
    description:
      'Event-type-specific payload (Section 46) — shape varies by eventType.',
  })
  data!: unknown;

  @ApiProperty({ nullable: true })
  previousHash!: string | null;

  @ApiProperty()
  eventHash!: string;

  @ApiProperty({ required: false })
  agentId?: string;

  @ApiProperty({ required: false })
  taskId?: string;

  @ApiProperty({ required: false })
  toolId?: string;

  @ApiProperty({ required: false })
  actionId?: string;

  @ApiProperty({ required: false })
  decision?: string;

  @ApiProperty({ required: false, minimum: 0, maximum: 100 })
  riskScore?: number;
}

/** `GET /audit`'s response envelope — see `AgentListResponseDto`'s identical shape/doc comment (cursor here is an OpenSearch `search_after` token, not a Prisma one — see `AuditSearchService`'s doc comment). */
export class AuditSearchResponseDto {
  @ApiProperty({ type: () => AuditEventSearchResultDto, isArray: true })
  items!: AuditEventSearchResultDto[];

  @ApiProperty({ nullable: true })
  nextCursor!: string | null;
}
