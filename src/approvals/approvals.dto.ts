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

  @ApiProperty({ nullable: true, format: 'uuid' })
  policyVersionId!: string | null;

  @ApiProperty({ enum: ['PENDING', 'APPROVED', 'DENIED', 'EXPIRED'] })
  status!: string;

  @ApiProperty({ format: 'date-time' })
  requestedAt!: Date;

  @ApiProperty({ format: 'date-time' })
  expiresAt!: Date;
}

/** `GET /approvals`'s response envelope — see `AgentListResponseDto`'s identical shape/doc comment. */
export class ApprovalRequestListResponseDto {
  @ApiProperty({ type: () => ApprovalRequestSummaryDto, isArray: true })
  items!: ApprovalRequestSummaryDto[];

  @ApiProperty({ nullable: true })
  nextCursor!: string | null;
}
