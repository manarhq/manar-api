import { ApiProperty } from '@nestjs/swagger';

/** Mirrors `CreateAgentRequestSchema` (`agents.validation.ts`) — the actual runtime-enforced shape; kept in sync by hand since this codebase's Zod-first validation convention doesn't derive Swagger DTOs from Zod schemas. */
export class CreateAgentRequestDto {
  @ApiProperty({
    description:
      "Lowercase alphanumeric with hyphens. Combined with the tenant slug to form this agent's SPIFFE-like `identifier` (`agent://<tenantSlug>/<slug>`).",
    example: 'edr-triage-bot',
    minLength: 1,
    maxLength: 63,
    pattern: '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$',
  })
  slug!: string;

  @ApiProperty({
    example: 'EDR Triage Bot',
    minLength: 1,
    maxLength: 200,
  })
  displayName!: string;
}

/** Mirrors what `AgentsController.createAgent` actually returns (a subset of the `Agent` Prisma model). */
export class CreateAgentResponseDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({ example: 'edr-triage-bot' })
  slug!: string;

  @ApiProperty({ example: 'agent://acme-corp/edr-triage-bot' })
  identifier!: string;

  @ApiProperty({ example: 'EDR Triage Bot' })
  displayName!: string;

  @ApiProperty({
    description:
      'Always `PENDING_ENROLLMENT` immediately after creation — an agent has no certificate yet, only a record. Transitions to `ACTIVE` once it completes `POST /agents/enroll`.',
    enum: ['PENDING_ENROLLMENT', 'ACTIVE', 'REVOKED', 'KILLED'],
    example: 'PENDING_ENROLLMENT',
  })
  status!: string;

  @ApiProperty({ format: 'date-time' })
  createdAt!: Date;
}

/** `POST /agents/:id/enrollment-tokens`'s response — the *only* response that ever carries the raw token (see `AgentsController.createEnrollmentToken`'s doc comment; never persisted or retrievable again). */
export class CreateEnrollmentTokenResponseDto {
  @ApiProperty({
    description:
      'The raw, single-use enrollment token. Give this to the agent process out-of-band — it is never retrievable again once this response is sent.',
  })
  token!: string;

  @ApiProperty({
    format: 'date-time',
    description:
      'Short TTL (15 minutes) — see AgentsService.ENROLLMENT_TOKEN_TTL_MS.',
  })
  expiresAt!: Date;
}

/** Mirrors `RevokeAgentRequestSchema`. */
export class RevokeAgentRequestDto {
  @ApiProperty({
    minLength: 1,
    maxLength: 500,
    example: 'Compromised host, rotating identity',
  })
  reason!: string;
}

/** Shared by `POST /agents/:id/revoke` and `POST /tasks/:id/revoke` — both controllers return this exact literal shape. */
export class RevokeStatusResponseDto {
  @ApiProperty({ enum: ['REVOKED'], example: 'REVOKED' })
  status!: 'REVOKED';
}
