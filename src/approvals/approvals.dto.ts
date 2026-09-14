import { ApiProperty } from '@nestjs/swagger';

/** Mirrors `DecideApprovalRequestSchema`. */
export class DecideApprovalRequestDto {
  @ApiProperty({ enum: ['APPROVE', 'DENY'] })
  decision!: 'APPROVE' | 'DENY';

  @ApiProperty({ required: false, maxLength: 1000 })
  reason?: string;
}

/**
 * Mirrors `ApprovalsController.decide`'s actual response (Phase 14
 * security cleanup 1 — see that method's own doc comment for the full
 * rationale). `status`/`decision` are the workflow's real, final outcome —
 * this handler now synchronously awaits `ApprovalWorkflow`'s result before
 * responding, rather than returning immediately post-signal. For two
 * genuinely concurrent `decide` calls on the same request, both responses
 * report the one decision that actually took effect (first-signal-wins),
 * never a discarded submission. `decision` is only present when `status`
 * is `APPROVED`/`DENIED`; a workflow that resolved `EXPIRED` (the caller's
 * signal lost a race against the request's own timeout) has no decision
 * to report.
 */
export class DecideApprovalResponseDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({
    enum: ['APPROVED', 'DENIED', 'EXPIRED'],
    example: 'APPROVED',
    description:
      "ApprovalWorkflow's real terminal outcome, not the pre-signal PENDING status.",
  })
  status!: 'APPROVED' | 'DENIED' | 'EXPIRED';

  @ApiProperty({
    enum: ['APPROVE', 'DENY'],
    required: false,
    description:
      'The decision that actually took effect. Absent only when `status` is EXPIRED.',
  })
  decision?: 'APPROVE' | 'DENY';
}

/** One row of `GET /approvals`'s paginated list — see `ApprovalRequestService.listApprovalRequests`. */
export class ApprovalRequestSummaryDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({ format: 'uuid' })
  taskId!: string;

  @ApiProperty({ format: 'uuid' })
  agentId!: string;

  @ApiProperty()
  toolId!: string;

  @ApiProperty()
  actionId!: string;

  @ApiProperty()
  resource!: string;

  @ApiProperty({ minimum: 0, maximum: 100 })
  riskScore!: number;

  @ApiProperty({ type: String, nullable: true, format: 'uuid' })
  policyVersionId!: string | null;

  @ApiProperty({ enum: ['PENDING', 'APPROVED', 'DENIED', 'EXPIRED'] })
  status!: string;

  @ApiProperty({ format: 'date-time' })
  requestedAt!: Date;

  @ApiProperty({ format: 'date-time' })
  expiresAt!: Date;
}

/**
 * `GET /approvals/:id` (release 2026-11-11, brief §3.4) — the exact action
 * under review.
 *
 * Every "separate" field pair here exists because the brief requires two
 * things not to be blended: deterministic factors versus AI signals, and
 * "not recorded" versus zero. A single `riskScore` with one anonymous
 * reason list is not something an approver can reason about.
 */
export class ApprovalRequestDetailDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({ format: 'uuid' })
  taskId!: string;

  @ApiProperty({ format: 'uuid' })
  agentId!: string;

  @ApiProperty()
  toolId!: string;

  @ApiProperty()
  actionId!: string;

  @ApiProperty()
  resource!: string;

  @ApiProperty({ enum: ['PENDING', 'APPROVED', 'DENIED', 'EXPIRED'] })
  status!: string;

  @ApiProperty({ format: 'date-time' })
  requestedAt!: Date;

  @ApiProperty({ format: 'date-time' })
  expiresAt!: Date;

  @ApiProperty({
    type: 'object',
    additionalProperties: true,
    description:
      'The invocation parameters, with credential-shaped values withheld. Redaction is KEY-NAME based, not content-based DLP: a secret under an innocuous key is not withheld. See redactedKeyPaths.',
  })
  params!: unknown;

  @ApiProperty({
    type: String,
    isArray: true,
    description:
      'Dotted paths of every withheld value. Empty means nothing was withheld — a positive statement, not an absence of information.',
  })
  redactedKeyPaths!: string[];

  @ApiProperty({
    description:
      'True when the parameter structure was too deep or too wide to render in full. The reviewer is looking at an incomplete object.',
  })
  parametersTruncated!: boolean;

  @ApiProperty({
    description:
      'sha256 of the exact {taskId, toolId, actionId, resource, params} tuple an issued AuthorizationGrant is bound to. Recomputed from the stored row on every read.',
  })
  parameterDigest!: string;

  @ApiProperty({ minimum: 0, maximum: 100 })
  riskScore!: number;

  @ApiProperty({
    type: Number,
    nullable: true,
    description:
      'null means NOT RECORDED (a row predating the breakdown migration) — never zero.',
  })
  deterministicRiskScore!: number | null;

  @ApiProperty({
    type: Number,
    nullable: true,
    description:
      'null means no advisory signal was available (unreachable, timed out, circuit open, or a fail-secure marker) — it never means the AI scored it zero.',
  })
  aiAdvisoryScore!: number | null;

  @ApiProperty({
    type: Number,
    nullable: true,
    description: 'The Task.riskCeiling riskScore was compared against.',
  })
  taskRiskCeiling!: number | null;

  @ApiProperty({
    type: String,
    nullable: true,
    enum: ['policy_requires_approval', 'risk_ceiling_exceeded'],
    description:
      'null on rows predating the migration — render as "not recorded".',
  })
  requiredReason!: string | null;

  @ApiProperty({ type: String, isArray: true })
  deterministicReasonCodes!: string[];

  @ApiProperty({
    type: String,
    isArray: true,
    description:
      'Risk contributions attributed to the AI advisory signal (ai_advisory_* codes), kept separate from deterministic ones.',
  })
  aiAdvisoryReasonCodes!: string[];

  @ApiProperty({ type: String, nullable: true, format: 'uuid' })
  policyVersionId!: string | null;

  @ApiProperty({
    type: 'object',
    nullable: true,
    additionalProperties: true,
    description:
      'What this action does, from the ToolAction row: actionName, mutating, destructive, classification. null when the action row is no longer resolvable — reported as unknown rather than guessed.',
  })
  expectedEffect!: Record<string, unknown> | null;

  @ApiProperty({
    type: 'array',
    items: { type: 'object', additionalProperties: true },
    description: 'Decisions recorded on this request, oldest first.',
  })
  decisions!: Record<string, unknown>[];

  @ApiProperty({
    description: 'Whether an AuthorizationGrant was issued for this request.',
  })
  grantIssued!: boolean;

  @ApiProperty({
    type: Date,
    nullable: true,
    format: 'date-time',
    description: 'When the single-use grant was redeemed, if it was.',
  })
  grantConsumedAt!: Date | null;
}

/** `GET /approvals`'s response envelope — see `AgentListResponseDto`'s identical shape/doc comment. */
export class ApprovalRequestListResponseDto {
  @ApiProperty({ type: () => ApprovalRequestSummaryDto, isArray: true })
  items!: ApprovalRequestSummaryDto[];

  @ApiProperty({ nullable: true })
  nextCursor!: string | null;
}
