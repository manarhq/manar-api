import { ApiProperty } from '@nestjs/swagger';

/** Mirrors `DomainEventEnvelope` (`../domain-event-envelope.ts`) — the JSON payload of each `event: audit-event` SSE frame `GET /events/live` emits. */
export class LiveAuditEventEnvelopeDto {
  @ApiProperty({ format: 'uuid' })
  eventId!: string;

  @ApiProperty({
    description: "See Section 29's event-type catalog (audit-event-types.ts).",
  })
  eventType!: string;

  @ApiProperty({ example: 1 })
  eventVersion!: number;

  @ApiProperty({ format: 'uuid' })
  tenantId!: string;

  @ApiProperty({ format: 'date-time' })
  timestamp!: string;

  @ApiProperty({ format: 'uuid' })
  correlationId!: string;

  @ApiProperty({
    type: 'object',
    properties: {
      type: { type: 'string', enum: ['human', 'agent', 'system', 'staff'] },
      id: { type: 'string' },
      display: {
        type: 'string',
        description: 'Staff only: "Ali · Manar Sales"',
      },
    },
  })
  actor!: {
    type: 'human' | 'agent' | 'system' | 'staff';
    id: string;
    display?: string;
  };

  @ApiProperty({
    type: 'object',
    additionalProperties: true,
    description: 'Heterogeneous, varies per eventType.',
  })
  data!: unknown;

  @ApiProperty({ required: false, nullable: true, type: String })
  previousHash?: string | null;

  @ApiProperty({ required: false })
  eventHash?: string;

  @ApiProperty({ required: false })
  sequence?: number;
}
