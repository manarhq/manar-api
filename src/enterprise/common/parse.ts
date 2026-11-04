import { BadRequestException } from '@nestjs/common';
import type { z } from 'zod';

/** zod parse or 400 with the field paths only (never the submitted values). */
export function parseOr400<S extends z.ZodType>(
  schema: S,
  value: unknown,
): z.infer<S> {
  const r = schema.safeParse(value);
  if (!r.success)
    throw new BadRequestException({
      code: 'invalid_body',
      fields: r.error.issues.map((i) => i.path.join('.') || '(root)'),
    });
  return r.data;
}
