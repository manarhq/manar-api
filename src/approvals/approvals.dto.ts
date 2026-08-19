import { ApiProperty } from '@nestjs/swagger';

/** Mirrors `DecideApprovalRequestSchema`. */
export class DecideApprovalRequestDto {
  @ApiProperty({ enum: ['APPROVE', 'DENY'] })
  decision!: 'APPROVE' | 'DENY';

  @ApiProperty({ required: false, maxLength: 1000 })
  reason?: string;
}

/**
 * Mirrors `ApprovalsController.decide`'s actual response. Note: `status`
 * is the `ApprovalRequest.status` read *before* the decision signal was
 * sent, and this handler returns as soon as the signal is delivered (not
 * once the workflow has actually processed it) — so `status` here is
 * always `"PENDING"` in practice, never the eventual `APPROVED`/`DENIED`
 * outcome. Poll `GET /agent/v1/approvals/:id` (agent-facing) or re-fetch
 * via another surface to observe the real outcome. Documented as-is per
 * this phase's "reflect actual behavior" scope.
 */
export class DecideApprovalResponseDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({
    enum: ['PENDING', 'APPROVED', 'DENIED', 'EXPIRED'],
    example: 'PENDING',
    description: 'In practice always "PENDING" — see class doc comment.',
  })
  status!: string;

  @ApiProperty({
    enum: ['APPROVE', 'DENY'],
    description: 'Echoes the decision just submitted.',
  })
  decision!: 'APPROVE' | 'DENY';
}
