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
    description:
      "Present only when valid=false: the AuditEvent.id where verification first failed, 'audit_partition_state:<n>' for a partition whose tail disagrees with its bookkeeping row, or 'checkpoint:<seq>' for a signed checkpoint that fails.",
  })
  brokenAt?: string;
}

/** `GET /audit/checkpoints/public-key`. */
export class CheckpointPublicKeyDto {
  @ApiProperty({ example: '3f9a1c0b2d4e5f60' })
  keyId!: string;

  @ApiProperty({ enum: ['Ed25519'] })
  algorithm!: 'Ed25519';

  @ApiProperty({ description: 'SPKI PEM.' })
  publicKeyPem!: string;
}

export class MerkleProofStepDto {
  @ApiProperty({ enum: ['L', 'R'], description: "The sibling's side." })
  side!: 'L' | 'R';

  @ApiProperty({ description: 'sha256 hex' })
  hash!: string;
}

export class SealedCheckpointDto {
  @ApiProperty({ description: 'Decimal string.' })
  seq!: string;

  @ApiProperty({ format: 'date-time' })
  createdAt!: string;

  @ApiProperty({
    description:
      '`{ partition, seq, eventHash }` for every partition with events.',
    type: 'array',
    items: { type: 'object' },
  })
  partitionHeads!: unknown[];

  @ApiProperty({
    description:
      '`{ partition, fromSeq, toSeq, root }` for each partition that advanced.',
    type: 'array',
    items: { type: 'object' },
  })
  roots!: unknown[];

  @ApiProperty({ nullable: true, type: String })
  previousCheckpointHash!: string | null;

  @ApiProperty()
  checkpointHash!: string;

  @ApiProperty({
    description:
      'Base64 Ed25519 signature over the 32 bytes of checkpointHash.',
  })
  signature!: string;

  @ApiProperty()
  keyId!: string;
}

/** `GET /audit/events/:id/proof`. */
export class AuditEventProofDto {
  @ApiProperty({ format: 'uuid' })
  eventId!: string;

  @ApiProperty({ minimum: 0, maximum: 63 })
  partition!: number;

  @ApiProperty({ description: 'Decimal string.' })
  partitionSeq!: string;

  @ApiProperty({ description: 'The event hash (leaf).' })
  leaf!: string;

  @ApiProperty({ type: [MerkleProofStepDto] })
  proof!: MerkleProofStepDto[];

  @ApiProperty({ description: 'The signed root this proof ends at.' })
  root!: string;

  @ApiProperty({ type: SealedCheckpointDto })
  checkpoint!: SealedCheckpointDto;
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
