import { ApiProperty } from '@nestjs/swagger';

/**
 * The shape Nest's built-in `HttpException` subclasses (`BadRequestException`,
 * `NotFoundException`, `ConflictException`, `ForbiddenException`,
 * `UnauthorizedException`, ...) serialize to by default — this codebase
 * never installs a custom exception filter that changes it (see every
 * controller's `mapXErrors`/`try`/`catch` blocks, which all just `throw`
 * one of these). Documented once here and referenced by every module's
 * `@ApiResponse({ type: ErrorResponseDto })` rather than redefined per
 * module.
 */
export class ErrorResponseDto {
  @ApiProperty({ example: 400 })
  statusCode!: number;

  @ApiProperty({
    description:
      'A human-readable message, or (only for class-validator-style array errors, which this codebase does not use) an array of them.',
    oneOf: [{ type: 'string' }, { type: 'array', items: { type: 'string' } }],
    example: 'Invalid request body',
  })
  message!: string | string[];

  @ApiProperty({ example: 'Bad Request' })
  error!: string;
}
