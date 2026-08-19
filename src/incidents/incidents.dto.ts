import { ApiProperty } from '@nestjs/swagger';

const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
const STATUSES = ['OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED'] as const;

/** Mirrors `CreateIncidentSchema` (`incidents.validation.ts`). */
export class CreateIncidentRequestDto {
  @ApiProperty({
    maxLength: 200,
    example: 'Suspected credential compromise on WS-042',
  })
  title!: string;

  @ApiProperty({ maxLength: 5000 })
  description!: string;

  @ApiProperty({ enum: SEVERITIES })
  severity!: (typeof SEVERITIES)[number];

  @ApiProperty({
    required: false,
    type: String,
    isArray: true,
    description:
      'AuditEvent.correlationId values this incident is linked to — see docs/audit-chain.md. Defaults to an empty array.',
  })
  relatedCorrelationIds?: string[];
}

/** Mirrors `UpdateIncidentSchema` — a partial update, at least one field required. */
export class UpdateIncidentRequestDto {
  @ApiProperty({ required: false, maxLength: 200 })
  title?: string;

  @ApiProperty({ required: false, maxLength: 5000 })
  description?: string;

  @ApiProperty({ required: false, enum: SEVERITIES })
  severity?: (typeof SEVERITIES)[number];

  @ApiProperty({
    required: false,
    enum: STATUSES,
    description:
      'A status transition -- setting RESOLVED (from a non-RESOLVED status) stamps resolvedAt. Audited (incident.status_changed) whenever this actually changes the current status.',
  })
  status?: (typeof STATUSES)[number];

  @ApiProperty({ required: false, type: String, isArray: true })
  relatedCorrelationIds?: string[];
}

/** One `Incident` row — see `IncidentsService`. */
export class IncidentSummaryDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty()
  title!: string;

  @ApiProperty()
  description!: string;

  @ApiProperty({ enum: SEVERITIES })
  severity!: (typeof SEVERITIES)[number];

  @ApiProperty({ enum: STATUSES })
  status!: (typeof STATUSES)[number];

  @ApiProperty({ type: String, isArray: true })
  relatedCorrelationIds!: string[];

  @ApiProperty({
    format: 'uuid',
    description: 'UserProfile ID of the creator.',
  })
  createdBy!: string;

  @ApiProperty({ format: 'date-time' })
  createdAt!: Date;

  @ApiProperty({ nullable: true, format: 'date-time' })
  resolvedAt!: Date | null;
}

/** `GET /incidents`'s response envelope — see `AgentListResponseDto`'s identical shape/doc comment. */
export class IncidentListResponseDto {
  @ApiProperty({ type: () => IncidentSummaryDto, isArray: true })
  items!: IncidentSummaryDto[];

  @ApiProperty({ nullable: true })
  nextCursor!: string | null;
}
