import { BadRequestException } from '@nestjs/common';
import type { z } from 'zod';

/** Validates a request body; 400 `invalid_request` with the field paths, never the values. */
export function parse<T extends z.ZodType>(
  schema: T,
  body: unknown,
): z.infer<T> {
  const r = schema.safeParse(body ?? {});
  if (!r.success)
    throw new BadRequestException({
      code: 'invalid_request',
      message: 'Check the details and try again.',
      fields: r.error.issues.map((i) => i.path.join('.')),
    });
  return r.data;
}
