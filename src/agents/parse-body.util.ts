import { BadRequestException } from '@nestjs/common';
import type { ZodType } from 'zod';

/** Parses an unknown request body against `schema`, throwing a 400 (no stack trace leaked, matching JwtAuthGuard's error-handling convention) on failure. */
export function parseBodyOrThrow<T>(schema: ZodType<T>, body: unknown): T {
  const result = schema.safeParse(body);
  if (!result.success) {
    throw new BadRequestException(
      `Invalid request body: ${result.error.issues.map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`).join('; ')}`,
    );
  }
  return result.data;
}
