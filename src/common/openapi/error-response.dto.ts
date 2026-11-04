import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class FieldProblemDto {
  @ApiProperty({ example: 'name' })
  field!: string;

  @ApiProperty({ example: 'must not be empty' })
  message!: string;
}

/**
 * The error envelope every route returns (`src/common/errors/error-envelope.filter.ts`).
 * Documented once here and referenced by every module's `@ApiResponse({ type: ErrorResponseDto })`.
 * Some routes add fields of their own (`reason`, `decision`, ...); they are kept as thrown.
 */
export class ErrorResponseDto {
  @ApiProperty({ example: 400 })
  statusCode!: number;

  @ApiProperty({
    description:
      'Plain words for a person: what happened and what to do. Never a stack trace or driver text.',
    example: 'Some details need fixing: name must not be empty.',
  })
  message!: string;

  @ApiProperty({ example: 'Bad Request' })
  error!: string;

  @ApiProperty({
    description:
      'Reference code for this occurrence; support finds the full details in the logs with it.',
    example: 'MNR-7F3K2Q',
  })
  reference!: string;

  @ApiPropertyOptional({
    description: 'The request correlation id (x-correlation-id).',
  })
  correlationId?: string;

  @ApiPropertyOptional({
    type: [FieldProblemDto],
    description: 'Validation failures, one per field (400 only).',
  })
  fields?: FieldProblemDto[];
}
