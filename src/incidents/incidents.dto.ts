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

/** Mirrors `SummarizeIncidentSchema` (Phase 10c). */
export class SummarizeIncidentRequestDto {
  @ApiProperty({
    required: false,
    format: 'uuid',
    description:
      "An existing Incident (must belong to the caller's own tenant). Its title/description and the AuditEvents matching its relatedCorrelationIds are included as context.",
  })
  incidentId?: string;

  @ApiProperty({
    required: false,
    maxLength: 5000,
    description:
      "Additional free-text context, combined with incidentId's own title/description when both are provided.",
  })
  description?: string;

  @ApiProperty({
    required: false,
    type: String,
    isArray: true,
    description:
      "Explicit AuditEvent IDs to include as context, in addition to any resolved from incidentId. Always resolved against the caller's own tenant database — an id belonging to another tenant is silently omitted, never fetched.",
  })
  auditEventIds?: string[];
}

/** Mirrors `IncidentSummaryAdvisory` (`ai-advisory-client.service.ts`). */
export class IncidentSummaryAdvisoryDto {
  @ApiProperty()
  summary!: string;

  @ApiProperty({ type: String, isArray: true })
  keyEvents!: string[];

  @ApiProperty({
    description: 'Best-effort, advisory-only hypothesis — never confirmed.',
  })
  probableRootCause!: string;

  @ApiProperty({ type: String, isArray: true })
  recommendedNextSteps!: string[];

  @ApiProperty({ minimum: 0, maximum: 1 })
  confidence!: number;

  @ApiProperty()
  explanation!: string;
}

/**
 * `POST /incidents/summarize`'s response. `available: false` (with
 * `result: null`) means manar-ai was unreachable, timed out, circuit-open,
 * or returned its own documented zero-confidence "analysis failed" marker
 * — never a crash, and never a fabricated-looking summary presented as
 * real (Section 80's fail-secure invariant, applied to this advisory-only
 * endpoint the same way Phase 10b already applies it to the authorization
 * pipeline).
 */
export class SummarizeIncidentResponseDto {
  @ApiProperty()
  available!: boolean;

  @ApiProperty({ nullable: true, type: () => IncidentSummaryAdvisoryDto })
  result!: IncidentSummaryAdvisoryDto | null;

  @ApiProperty({
    description: 'How many AuditEvents were included as context.',
  })
  contextEventCount!: number;
}
