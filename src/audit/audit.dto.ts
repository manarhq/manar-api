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
