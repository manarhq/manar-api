import { ApiProperty } from '@nestjs/swagger';

/** Mirrors `ActivateKillSwitchRequestSchema` (`kill-switches.validation.ts`). */
export class ActivateKillSwitchRequestDto {
  @ApiProperty({
    required: false,
    minLength: 1,
    maxLength: 500,
    example: 'Suspected credential compromise — isolating immediately',
  })
  reason?: string;
}

/** Common shape every tenant-scoped (`TENANT`/`AGENT_GROUP`/`AGENT`/`TOOL`) activation endpoint returns. */
export class KillSwitchStatusResponseDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({
    enum: ['TENANT', 'AGENT_GROUP', 'AGENT', 'TOOL'],
    example: 'AGENT',
  })
  scope!: string;

  @ApiProperty({ nullable: true, format: 'uuid' })
  targetId!: string | null;

  @ApiProperty()
  active!: boolean;

  @ApiProperty({ nullable: true })
  reason!: string | null;

  @ApiProperty({ format: 'date-time' })
  activatedAt!: Date;
}

/** `POST /kill-switches/platform`'s response — the control-DB singleton row has no per-tenant `id`/`targetId`. */
export class PlatformKillSwitchStatusResponseDto {
  @ApiProperty()
  active!: boolean;

  @ApiProperty({ nullable: true })
  reason!: string | null;

  @ApiProperty({ nullable: true, format: 'date-time' })
  activatedAt!: Date | null;
}

/** Every `.../kill-switch/deactivate` endpoint's response. */
export class KillSwitchDeactivatedResponseDto {
  @ApiProperty({ enum: ['INACTIVE'], example: 'INACTIVE' })
  status!: 'INACTIVE';
}
