import { BadRequestException } from '@nestjs/common';
import type { ZodType, core } from 'zod';

export interface FieldProblem {
  /** Dotted path into the body (`rules.0.name`), empty for the body itself. */
  field: string;
  message: string;
}

const FORMATS: Record<string, string> = {
  email: 'must be a valid email address',
  url: 'must be a valid web address',
  uuid: 'must be a valid ID',
  datetime: 'must be a valid date and time',
  date: 'must be a valid date',
  regex: 'is not in the expected format',
};

/** One zod issue in words a person can act on (zod's own text reads "Too small: expected string to have >=3 characters"). */
export function describeIssue(issue: core.$ZodIssue, body?: unknown): string {
  // zod 4 does not report the input, so a missing field is found by walking the body.
  const missing =
    issue.path.length > 0 &&
    issue.path.reduce<unknown>(
      (v, k) =>
        v == null ? undefined : (v as Record<PropertyKey, unknown>)[k],
      body,
    ) === undefined;
  if (
    missing &&
    (issue.code === 'invalid_type' || issue.code === 'invalid_value')
  )
    return 'is required';
  switch (issue.code) {
    case 'invalid_type':
      return `must be a ${issue.expected}`;
    case 'too_small': {
      const n = Number(issue.minimum);
      if (issue.origin === 'string')
        return n <= 1
          ? 'must not be empty'
          : `must be at least ${n} characters`;
      if (issue.origin === 'array' || issue.origin === 'set')
        return `needs at least ${n} item${n === 1 ? '' : 's'}`;
      return `must be ${issue.inclusive ? 'at least' : 'more than'} ${n}`;
    }
    case 'too_big': {
      const n = Number(issue.maximum);
      if (issue.origin === 'string') return `must be at most ${n} characters`;
      if (issue.origin === 'array' || issue.origin === 'set')
        return `can have at most ${n} item${n === 1 ? '' : 's'}`;
      return `must be ${issue.inclusive ? 'at most' : 'less than'} ${n}`;
    }
    case 'invalid_format':
      return FORMATS[issue.format] ?? 'is not in the expected format';
    case 'invalid_value':
      return `must be one of: ${issue.values.map(String).join(', ')}`;
    case 'unrecognized_keys':
      return `has fields we don't recognise: ${issue.keys.join(', ')}`;
    default:
      // `custom` and refinements carry a message their author wrote.
      return issue.message;
  }
}

export function fieldProblems(
  issues: readonly core.$ZodIssue[],
  body?: unknown,
): FieldProblem[] {
  return issues.map((issue) => ({
    field: issue.path.map(String).join('.'),
    message: describeIssue(issue, body),
  }));
}

/**
 * Parses an unknown request body against `schema`. On failure: a 400 whose `message` names each
 * field and what is wrong with it, plus `fields` for forms that highlight them. No stack, no input echo.
 */
export function parseBodyOrThrow<T>(schema: ZodType<T>, body: unknown): T {
  const result = schema.safeParse(body);
  if (!result.success) {
    const fields = fieldProblems(result.error.issues, body);
    const listed = fields
      .slice(0, 5)
      .map((f) => `${f.field || 'The request'} ${f.message}`)
      .join('; ');
    throw new BadRequestException({
      message: `Some details need fixing: ${listed}.`,
      fields,
    });
  }
  return result.data;
}
