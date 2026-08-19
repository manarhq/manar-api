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
 * Mirrors what `TasksController.createTask` actually returns.
 *
 * Phase 11b Part 1 fix: an earlier phase's OpenAPI documentation work
 * (Phase 11a Part 1) found and documented — but, per that phase's
 * narrower "reflect actual behavior, don't fix bugs" scope, deliberately
 * did not fix — that this endpoint populated `createdAt` from
 * `task.startsAt` rather than `Task.createdAt`. This phase's scope
 * explicitly allows fixing exactly this kind of trivial, clearly-correct
 * bug found while working nearby, so `TasksController.createTask` now
 * returns the real `Task.createdAt` here.
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

  @ApiProperty({ format: 'date-time' })
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

/** One row of `GET /tasks`'s paginated list — see `TasksService.listTasks`. */
export class TaskSummaryDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({ example: 'Investigate suspicious login' })
  name!: string;

  @ApiProperty({ nullable: true })
  description!: string | null;

  @ApiProperty({
    enum: ['PENDING', 'ACTIVE', 'EXPIRED', 'REVOKED', 'COMPLETED'],
    example: 'ACTIVE',
  })
  status!: string;

  @ApiProperty({ format: 'uuid' })
  assignedAgentId!: string;

  @ApiProperty({ format: 'uuid' })
  requesterId!: string;

  @ApiProperty({ format: 'uuid', nullable: true })
  parentTaskId!: string | null;

  @ApiProperty({ format: 'date-time' })
  startsAt!: Date;

  @ApiProperty({ format: 'date-time' })
  expiresAt!: Date;

  @ApiProperty({ minimum: 0, maximum: 100 })
  riskCeiling!: number;

  @ApiProperty({ format: 'date-time' })
  createdAt!: Date;
}

/** `GET /tasks`'s response envelope — see `AgentListResponseDto`'s identical shape/doc comment. */
export class TaskListResponseDto {
  @ApiProperty({ type: () => TaskSummaryDto, isArray: true })
  items!: TaskSummaryDto[];

  @ApiProperty({ nullable: true })
  nextCursor!: string | null;
}
