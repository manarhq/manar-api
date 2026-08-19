import { ApiProperty } from '@nestjs/swagger';

export class CreateWebhookEndpointRequestDto {
  @ApiProperty({ example: 'https://receiver.example.com/manar/webhook' })
  url!: string;

  @ApiProperty({
    type: [String],
    example: ['tool.invocation.completed', 'kill_switch.activated'],
    description:
      "Must name at least one real event type from Phase 9a's catalog (`AUDIT_EVENT_TYPES`).",
  })
  subscribedEventTypes!: string[];

  @ApiProperty({ required: false, default: true })
  enabled?: boolean;
}

export class UpdateWebhookEndpointRequestDto {
  @ApiProperty({ required: false })
  url?: string;

  @ApiProperty({ required: false, type: [String] })
  subscribedEventTypes?: string[];

  @ApiProperty({ required: false })
  enabled?: boolean;
}

/** The shape returned by every endpoint except creation — never carries the signing secret. */
export class WebhookEndpointResponseDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty()
  url!: string;

  @ApiProperty({ type: [String] })
  subscribedEventTypes!: string[];

  @ApiProperty()
  enabled!: boolean;

  @ApiProperty({ format: 'uuid' })
  createdBy!: string;

  @ApiProperty({ format: 'date-time' })
  createdAt!: Date;

  @ApiProperty({ format: 'date-time' })
  updatedAt!: Date;
}

/** `POST /webhooks`'s response — the ONLY time `secret` is ever returned in plaintext (see `WebhookRegistryService.create`'s doc comment). */
export class WebhookEndpointCreatedResponseDto extends WebhookEndpointResponseDto {
  @ApiProperty({
    description:
      'The HMAC signing secret, in plaintext, shown exactly once. Store it now — there is no endpoint to retrieve it again.',
  })
  secret!: string;
}

export class WebhookDeliveryResponseDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({ format: 'uuid' })
  webhookEndpointId!: string;

  @ApiProperty()
  eventId!: string;

  @ApiProperty()
  eventType!: string;

  @ApiProperty({ enum: ['PENDING', 'SUCCESS', 'FAILED'] })
  status!: string;

  @ApiProperty()
  attempts!: number;

  @ApiProperty({ nullable: true, format: 'date-time' })
  lastAttemptAt!: Date | null;

  @ApiProperty({ nullable: true })
  responseStatus!: number | null;

  @ApiProperty({ format: 'date-time' })
  createdAt!: Date;
}
