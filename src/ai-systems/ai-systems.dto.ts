import { ApiProperty } from '@nestjs/swagger';

/**
 * Release 2026-11-11 (brief §3.1) — Swagger DTOs for `/ai-systems`. These
 * classes exist only to describe request/response shapes to the OpenAPI
 * document (which `manar-web` regenerates its typed client from via
 * `pnpm api:codegen`); zod in `ai-systems.validation.ts` is what actually
 * validates. Same split every other module here uses.
 */

const LIFECYCLE_STATES = [
  'DRAFT',
  'REVIEW',
  'ACTIVE',
  'SUSPENDED',
  'RETIRED',
] as const;
const ENVIRONMENTS = ['DEVELOPMENT', 'STAGING', 'PRODUCTION'] as const;
const CLASSIFICATIONS = [
  'PUBLIC',
  'INTERNAL',
  'CONFIDENTIAL',
  'RESTRICTED',
] as const;
const COVERAGE_VALUES = [
  'GOVERNED',
  'OBSERVED_ONLY',
  'DECLARED_ONLY',
  'MONITORING_UNAVAILABLE',
] as const;

/** Mirrors `CreateAiSystemSchema`. */
export class CreateAiSystemRequestDto {
  @ApiProperty({
    maxLength: 64,
    example: 'claims-triage-assistant',
    description:
      'Lowercase kebab-case, unique per tenant, immutable after creation (it appears in deep links and exported evidence).',
  })
  slug!: string;

  @ApiProperty({ maxLength: 200, example: 'Claims triage assistant' })
  name!: string;

  @ApiProperty({
    maxLength: 2000,
    description: 'What this system is for, in business terms. Required.',
  })
  businessPurpose!: string;

  @ApiProperty({
    format: 'uuid',
    description:
      'UserProfile.id of the accountable owner. Verified to exist in this tenant before the record is written.',
  })
  ownerId!: string;

  @ApiProperty({ maxLength: 200, example: 'Claims Operations' })
  businessUnit!: string;

  @ApiProperty({ enum: ENVIRONMENTS })
  environment!: (typeof ENVIRONMENTS)[number];

  @ApiProperty({
    required: false,
    enum: CLASSIFICATIONS,
    description:
      'The classification of data this system is DECLARED to handle. Defaults to INTERNAL — the same safe default ToolAction.classification uses.',
  })
  dataClassification?: (typeof CLASSIFICATIONS)[number];

  @ApiProperty({
    required: false,
    maxLength: 100,
    description:
      'Declared, never verified. Drift between this and the API/AI service’s actually-configured provider is a governance finding, not something this field reconciles.',
  })
  declaredProvider?: string;

  @ApiProperty({ required: false, maxLength: 200 })
  declaredModel?: string;

  @ApiProperty({ maxLength: 4000 })
  riskRationale!: string;

  @ApiProperty({
    required: false,
    format: 'date-time',
    description:
      'When this record is next due for review. Absent means unscheduled — which the console renders as unscheduled, never as “not due”.',
  })
  nextReviewDate?: string;
}

/** Mirrors `UpdateAiSystemSchema`. `lifecycleState` is deliberately absent — use `POST /ai-systems/:id/transitions`. */
export class UpdateAiSystemRequestDto {
  @ApiProperty({ required: false, maxLength: 200 })
  name?: string;

  @ApiProperty({ required: false, maxLength: 2000 })
  businessPurpose?: string;

  @ApiProperty({ required: false, format: 'uuid' })
  ownerId?: string;

  @ApiProperty({ required: false, maxLength: 200 })
  businessUnit?: string;

  @ApiProperty({ required: false, enum: ENVIRONMENTS })
  environment?: (typeof ENVIRONMENTS)[number];

  @ApiProperty({ required: false, enum: CLASSIFICATIONS })
  dataClassification?: (typeof CLASSIFICATIONS)[number];

  @ApiProperty({
    required: false,
    nullable: true,
    description:
      'Explicit null clears the declaration; omit to leave unchanged.',
  })
  declaredProvider?: string | null;

  @ApiProperty({ required: false, nullable: true })
  declaredModel?: string | null;

  @ApiProperty({ required: false, maxLength: 4000 })
  riskRationale?: string;

  @ApiProperty({ required: false, nullable: true, format: 'date-time' })
  nextReviewDate?: string | null;

  @ApiProperty({
    maxLength: 1000,
    description:
      'Required. Every field on this DTO is material, so every update snapshots the prior state into the version history — an unexplained material change is not evidence of anything.',
  })
  changeReason!: string;
}

/** Mirrors `TransitionAiSystemSchema`. */
export class TransitionAiSystemRequestDto {
  @ApiProperty({
    enum: LIFECYCLE_STATES,
    description:
      'Target state. Allowed edges: DRAFT→REVIEW/RETIRED, REVIEW→ACTIVE/DRAFT/RETIRED, ACTIVE→SUSPENDED/RETIRED, SUSPENDED→ACTIVE/RETIRED. RETIRED is terminal.',
  })
  toState!: (typeof LIFECYCLE_STATES)[number];

  @ApiProperty({ maxLength: 1000 })
  reason!: string;
}

/** Mirrors `LinkAgentSchema`. */
export class LinkAgentRequestDto {
  @ApiProperty({ format: 'uuid' })
  agentId!: string;
}

/** Mirrors `LinkToolSchema`. */
export class LinkToolRequestDto {
  @ApiProperty({ format: 'uuid' })
  toolId!: string;
}

/** One `AiSystem` row, without derived coverage — the list-endpoint shape. */
export class AiSystemSummaryDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty()
  slug!: string;

  @ApiProperty()
  name!: string;

  @ApiProperty()
  businessPurpose!: string;

  @ApiProperty({ format: 'uuid' })
  ownerId!: string;

  @ApiProperty()
  businessUnit!: string;

  @ApiProperty({ enum: ENVIRONMENTS })
  environment!: (typeof ENVIRONMENTS)[number];

  @ApiProperty({ enum: LIFECYCLE_STATES })
  lifecycleState!: (typeof LIFECYCLE_STATES)[number];

  @ApiProperty({ enum: CLASSIFICATIONS })
  dataClassification!: (typeof CLASSIFICATIONS)[number];

  @ApiProperty({ nullable: true })
  declaredProvider!: string | null;

  @ApiProperty({ nullable: true })
  declaredModel!: string | null;

  @ApiProperty()
  riskRationale!: string;

  @ApiProperty({ nullable: true, format: 'date-time' })
  nextReviewDate!: string | null;

  @ApiProperty({ description: 'Incremented on every material change.' })
  version!: number;

  @ApiProperty({ format: 'date-time' })
  createdAt!: Date;

  @ApiProperty({ format: 'uuid' })
  createdBy!: string;

  @ApiProperty({ format: 'date-time' })
  updatedAt!: Date;
}

/**
 * Derived runtime coverage. Computed per request from real
 * `ToolInvocation` rows and `Agent.status` — never stored. The counts
 * travel with the verdict so the console can explain it without a second
 * request, and `MONITORING_UNAVAILABLE` is a real, distinct answer meaning
 * "the observation source could not be consulted", never "no activity".
 */
export class AiSystemCoverageDto {
  @ApiProperty({ enum: COVERAGE_VALUES })
  coverage!: (typeof COVERAGE_VALUES)[number];

  @ApiProperty()
  linkedAgentCount!: number;

  @ApiProperty({
    description:
      'How many linked agents are ACTIVE — i.e. would be subject to enforcement if they ran now. Separate from coverage on purpose.',
  })
  activeLinkedAgentCount!: number;

  @ApiProperty()
  observedAgentCount!: number;

  @ApiProperty({ nullable: true, format: 'date-time' })
  lastObservedAt!: Date | null;

  @ApiProperty()
  observationWindowDays!: number;
}

/** One linked agent, with its own last-observed timestamp so the UI can show why coverage reads the way it does. */
export class AiSystemLinkedAgentDto {
  @ApiProperty({ format: 'uuid' })
  agentId!: string;

  @ApiProperty()
  slug!: string;

  @ApiProperty()
  displayName!: string;

  @ApiProperty()
  status!: string;

  @ApiProperty({ format: 'date-time' })
  linkedAt!: Date;

  @ApiProperty({ format: 'uuid' })
  linkedBy!: string;

  @ApiProperty({ nullable: true, format: 'date-time' })
  lastObservedAt!: Date | null;
}

/** One linked tool. */
export class AiSystemLinkedToolDto {
  @ApiProperty({ format: 'uuid' })
  toolId!: string;

  @ApiProperty()
  name!: string;

  @ApiProperty({ format: 'date-time' })
  linkedAt!: Date;

  @ApiProperty({ format: 'uuid' })
  linkedBy!: string;
}

/** `GET /ai-systems/:id` — summary plus everything derived. */
export class AiSystemDetailDto extends AiSystemSummaryDto {
  @ApiProperty({ type: AiSystemCoverageDto })
  coverage!: AiSystemCoverageDto;

  @ApiProperty({ type: AiSystemLinkedAgentDto, isArray: true })
  linkedAgents!: AiSystemLinkedAgentDto[];

  @ApiProperty({ type: AiSystemLinkedToolDto, isArray: true })
  linkedTools!: AiSystemLinkedToolDto[];
}

/** `GET /ai-systems` — one cursor page. */
export class AiSystemListResponseDto {
  @ApiProperty({ type: AiSystemSummaryDto, isArray: true })
  items!: AiSystemSummaryDto[];

  @ApiProperty({
    nullable: true,
    description: 'Opaque cursor for the next page; null when exhausted.',
  })
  nextCursor!: string | null;
}

/** One entry of `GET /ai-systems/:id/versions`. */
export class AiSystemVersionDto {
  @ApiProperty({ description: 'The version this snapshot replaces.' })
  version!: number;

  @ApiProperty({
    type: 'object',
    additionalProperties: true,
    description: 'The governed field set as it stood before the change.',
  })
  snapshot!: Record<string, unknown>;

  @ApiProperty()
  changeReason!: string;

  @ApiProperty({ format: 'uuid' })
  changedBy!: string;

  @ApiProperty({ format: 'date-time' })
  changedAt!: Date;
}

/** One entry of `GET /ai-systems/:id/transitions`. */
export class AiSystemTransitionDto {
  @ApiProperty({ enum: LIFECYCLE_STATES })
  fromState!: (typeof LIFECYCLE_STATES)[number];

  @ApiProperty({ enum: LIFECYCLE_STATES })
  toState!: (typeof LIFECYCLE_STATES)[number];

  @ApiProperty()
  reason!: string;

  @ApiProperty({ format: 'uuid' })
  actorId!: string;

  @ApiProperty({ format: 'date-time' })
  at!: Date;
}

/** Link/unlink result. `false` means the assertion was already in (or already absent from) this state — a no-op, not an error. */
export class AiSystemLinkResultDto {
  @ApiProperty({ required: false })
  linked?: boolean;

  @ApiProperty({ required: false })
  unlinked?: boolean;
}
