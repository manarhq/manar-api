import { ApiProperty } from '@nestjs/swagger';

/** Mirrors `ToolActionSchema` (`src/authorization/grant-triples.ts`) — one (toolId, actionId) pair. */
export class ToolActionDto {
  @ApiProperty({ minLength: 1, maxLength: 128, example: 'siem' })
  toolId!: string;

  @ApiProperty({ minLength: 1, maxLength: 128, example: 'query' })
  actionId!: string;
}

/** Mirrors `ResourceSelectorSchema` — a resource pattern scoped to one tool, matched exactly or via the `"*"` wildcard sentinel. */
export class ResourceSelectorDto {
  @ApiProperty({ minLength: 1, maxLength: 128, example: 'siem' })
  toolId!: string;

  @ApiProperty({
    minLength: 1,
    maxLength: 2048,
    example: '*',
    description: 'A literal resource identifier, or the wildcard "*".',
  })
  pattern!: string;
}

/** Mirrors `CreateTaskRequestSchema` (`tasks.validation.ts`). */
export class CreateTaskRequestDto {
  @ApiProperty({
    minLength: 1,
    maxLength: 200,
    example: 'Investigate suspicious login',
  })
  name!: string;

  @ApiProperty({ required: false, maxLength: 2000 })
  description?: string;

  @ApiProperty({
    format: 'uuid',
    description: 'The Agent this task is assigned to.',
  })
  assignedAgentId!: string;

  @ApiProperty({
    type: () => ToolActionDto,
    isArray: true,
    maxItems: 100,
    default: [],
    description:
      'Cross-joined with allowedResourceSelectors (by toolId) to form the effective grant set — see grant-triples.ts.',
  })
  allowedToolActions!: ToolActionDto[];

  @ApiProperty({
    type: () => ResourceSelectorDto,
    isArray: true,
    maxItems: 100,
    default: [],
  })
  allowedResourceSelectors!: ResourceSelectorDto[];

  @ApiProperty({
    type: () => ToolActionDto,
    isArray: true,
    maxItems: 100,
    default: [],
    description:
      'Any (toolId, actionId) pair here is removed from the effective grant set even if also present in allowedToolActions — an explicit deny always wins.',
  })
  forbiddenActions!: ToolActionDto[];

  @ApiProperty({
    required: false,
    format: 'date-time',
    description: 'Defaults to "now" if omitted.',
  })
  startsAt?: Date;

  @ApiProperty({ format: 'date-time', description: 'Must be in the future.' })
  expiresAt!: Date;

  @ApiProperty({ required: false, nullable: true, type: Number, example: null })
  maxExecutions?: number | null;

  @ApiProperty({
    minimum: 0,
    maximum: 100,
    default: 20,
    description: 'Conservative default — see Task.riskCeiling.',
  })
  riskCeiling!: number;
}

/**
 * Mirrors what `TasksController.createTask` actually returns. Note:
 * despite the field name, `createdAt` here is populated from
 * `task.startsAt`, not `Task.createdAt` (see the controller — this is
 * documented as-is per this phase's "reflect actual behavior, don't fix
 * bugs" scope, not a typo in this DTO).
 */
export class CreateTaskResponseDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({
    enum: ['PENDING', 'ACTIVE', 'EXPIRED', 'REVOKED', 'COMPLETED'],
    example: 'ACTIVE',
  })
  status!: string;

  @ApiProperty({ format: 'uuid' })
  assignedAgentId!: string;

  @ApiProperty({ format: 'date-time' })
  expiresAt!: Date;

  @ApiProperty({
    format: 'date-time',
    description:
      "Actually the task's `startsAt` value, not its true creation timestamp — see class doc comment.",
  })
  createdAt!: Date;
}

/** Mirrors `RevokeTaskRequestSchema`. */
export class RevokeTaskRequestDto {
  @ApiProperty({
    minLength: 1,
    maxLength: 500,
    example: 'Investigation complete',
  })
  reason!: string;
}
