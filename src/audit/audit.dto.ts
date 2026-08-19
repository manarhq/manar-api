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

/**
 * `POST /audit/investigate`'s request body (Phase 10c). `filters` is the
 * exact same filter set `GET /audit`'s query params expose (Section 66) —
 * reused as-is, not a new query shape — narrowing which of the caller's
 * own tenant's AuditEvents become retrieved context. `tenantId` is never
 * one of these fields: it always comes from `AuthContext`, exactly like
 * `GET /audit` (see `AuditSearchService`'s doc comment) — this is the one
 * hard invariant this endpoint must never regress.
 */
export class InvestigateAuditRequestDto {
  @ApiProperty({
    minLength: 1,
    maxLength: 2000,
    example: 'Why was the endpoint-isolation action denied for agent X?',
  })
  question!: string;

  @ApiProperty({
    required: false,
    description: 'Comma-separated eventType values (OR).',
  })
  eventType?: string;

  @ApiProperty({ required: false })
  correlationId?: string;

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

  @ApiProperty({ required: false, type: Number })
  riskMin?: number;

  @ApiProperty({ required: false, type: Number })
  riskMax?: number;

  @ApiProperty({
    required: false,
    description: 'ISO-8601 inclusive lower bound.',
  })
  from?: string;

  @ApiProperty({
    required: false,
    description: 'ISO-8601 inclusive upper bound.',
  })
  to?: string;

  @ApiProperty({
    required: false,
    type: Number,
    description:
      'Max AuditEvents to retrieve as context, most recent first. Max 50, default 10.',
  })
  contextLimit?: number;
}

/** Mirrors `AuditInvestigationAdvisory` (`ai-advisory-client.service.ts`). */
export class AuditInvestigationAdvisoryDto {
  @ApiProperty({ description: 'Grounded only in the retrieved context.' })
  answer!: string;

  @ApiProperty({
    type: String,
    isArray: true,
    description: 'Which pieces of the retrieved context the answer relied on.',
  })
  citations!: string[];

  @ApiProperty({ minimum: 0, maximum: 1 })
  confidence!: number;

  @ApiProperty()
  explanation!: string;
}

/**
 * `POST /audit/investigate`'s response. `available: false` (with `result:
 * null`) means manar-ai was unreachable/timed out/circuit-open/returned
 * its own zero-confidence "investigation failed" marker — never a crash,
 * never a fabricated answer presented as authoritative.
 */
export class InvestigateAuditResponseDto {
  @ApiProperty()
  available!: boolean;

  @ApiProperty({ nullable: true, type: () => AuditInvestigationAdvisoryDto })
  result!: AuditInvestigationAdvisoryDto | null;

  @ApiProperty({
    description:
      "How many of the caller's own tenant's AuditEvents were retrieved and sent as context.",
  })
  contextEventCount!: number;
}
