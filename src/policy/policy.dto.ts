import { ApiProperty } from '@nestjs/swagger';

/** Mirrors `PolicyRuleSchema` (`policy-content.schema.ts`). */
export class PolicyRuleDto {
  @ApiProperty({
    required: false,
    maxLength: 200,
    description: 'Audit/debugging label only, never matched against.',
  })
  name?: string;

  @ApiProperty({
    example: '*',
    description: 'Exact toolId, or "*" for any tool.',
  })
  toolId!: string;

  @ApiProperty({
    example: '*',
    description: 'Exact actionId, or "*" for any action.',
  })
  actionId!: string;

  @ApiProperty({
    default: '*',
    example: '*',
    description: 'Exact resource identifier, or "*". Omitted means "*".',
  })
  resourcePattern!: string;

  @ApiProperty({ enum: ['ALLOW', 'DENY', 'REQUIRE_APPROVAL'] })
  effect!: 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL';

  @ApiProperty({
    required: false,
    minimum: 0,
    maximum: 100,
    description:
      "Additive contribution to RiskEngine's score when this rule matches.",
  })
  riskWeight?: number;

  @ApiProperty({
    required: false,
    minimum: 0,
    maximum: 100,
    description:
      'Minimum RiskEngine will clamp its score up to when this rule matches.',
  })
  riskFloor?: number;

  @ApiProperty({
    required: false,
    maxLength: 2000,
    description: 'Free-text rationale, never evaluated.',
  })
  description?: string;
}

/** Mirrors `PolicyContentSchema` — the declarative rule-content format `Policy`/`PolicyVersion` store. First-match-wins, in array order. */
export class PolicyContentDto {
  @ApiProperty({
    type: () => PolicyRuleDto,
    isArray: true,
    minItems: 1,
    maxItems: 200,
  })
  rules!: PolicyRuleDto[];
}

/**
 * Mirrors `CreatePolicyRequestSchema`. Exactly one of `content`/`contentYaml`
 * must be provided — never both, never neither (Section 21: JSON and YAML
 * submissions manipulate the same underlying model).
 */
export class CreatePolicyRequestDto {
  @ApiProperty({
    minLength: 1,
    maxLength: 200,
    example: 'High-risk EDR containment actions',
  })
  name!: string;

  @ApiProperty({ required: false, maxLength: 2000 })
  description?: string;

  @ApiProperty({
    required: false,
    type: () => PolicyContentDto,
    description:
      'The rule content as JSON. Mutually exclusive with contentYaml.',
  })
  content?: PolicyContentDto;

  @ApiProperty({
    required: false,
    description:
      'The rule content as a YAML string, parsed into the same PolicyContentSchema. Mutually exclusive with content.',
  })
  contentYaml?: string;

  @ApiProperty({ required: false, minLength: 1, maxLength: 500 })
  reason?: string;
}

/**
 * Mirrors `CreatePolicyVersionRequestSchema`. Exactly one of `content`,
 * `contentYaml`, or `rollbackToVersionId` must be provided.
 */
export class CreatePolicyVersionRequestDto {
  @ApiProperty({ required: false, type: () => PolicyContentDto })
  content?: PolicyContentDto;

  @ApiProperty({ required: false })
  contentYaml?: string;

  @ApiProperty({
    required: false,
    format: 'uuid',
    description:
      "Create a new DRAFT version whose content matches an existing version's content exactly (a rollback).",
  })
  rollbackToVersionId?: string;

  @ApiProperty({ required: false, minLength: 1, maxLength: 500 })
  reason?: string;
}

/** Mirrors `shapeVersion`'s output (`policy.controller.ts`) — the shape every endpoint that returns a `PolicyVersion` uses. */
export class PolicyVersionResponseDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({ format: 'uuid' })
  policyId!: string;

  @ApiProperty({ example: 1 })
  version!: number;

  @ApiProperty({ enum: ['DRAFT', 'PUBLISHED'] })
  status!: string;

  @ApiProperty({ type: () => PolicyContentDto })
  content!: PolicyContentDto;

  @ApiProperty({
    description:
      'sha256 hex of `content` after deterministic canonicalization.',
  })
  contentHash!: string;

  @ApiProperty({ format: 'uuid' })
  authorId!: string;

  @ApiProperty({ nullable: true, type: String })
  reason!: string | null;

  @ApiProperty({ nullable: true, type: String, format: 'uuid' })
  previousVersionId!: string | null;

  @ApiProperty({ nullable: true, type: String, format: 'date-time' })
  publishedAt!: string | null;

  @ApiProperty({ format: 'date-time' })
  createdAt!: Date;
}

/** `POST /policies`'s response. */
export class CreatePolicyResponseDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty()
  name!: string;

  @ApiProperty({ nullable: true, type: String })
  description!: string | null;

  @ApiProperty({ format: 'date-time' })
  createdAt!: Date;

  @ApiProperty({ type: () => PolicyVersionResponseDto })
  latestVersion!: PolicyVersionResponseDto;
}

/** `GET /policies/:id`'s response. */
export class GetPolicyResponseDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty()
  name!: string;

  @ApiProperty({ nullable: true, type: String })
  description!: string | null;

  @ApiProperty({ format: 'date-time' })
  createdAt!: Date;

  @ApiProperty({
    nullable: true,
    type: () => PolicyVersionResponseDto,
    description:
      'The current PUBLISHED version, or null if none has ever been published.',
  })
  currentVersion!: PolicyVersionResponseDto | null;
}
