import { z } from 'zod';

/**
 * Request-body validation for the `/agents` surface, using this
 * codebase's established Zod-first convention (`src/config/env.validation.ts`)
 * rather than introducing `class-validator`/`class-transformer` as a second
 * validation paradigm just for this module — there's no global
 * `ValidationPipe` wired up yet, so each controller method parses its own
 * body with these schemas and throws `BadRequestException` on failure (see
 * `parseOrThrowBadRequest` below).
 */

const SLUG_PATTERN = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;

export const CreateAgentRequestSchema = z.object({
  slug: z
    .string()
    .min(1)
    .max(63)
    .regex(SLUG_PATTERN, 'slug must be lowercase alphanumeric with hyphens'),
  displayName: z.string().min(1).max(200),
});
export type CreateAgentRequest = z.infer<typeof CreateAgentRequestSchema>;

export const RevokeAgentRequestSchema = z.object({
  reason: z.string().min(1).max(500),
});
export type RevokeAgentRequest = z.infer<typeof RevokeAgentRequestSchema>;

export const EnrollAgentRequestSchema = z.object({
  token: z.string().min(1),
  csr: z.string().min(1),
});
export type EnrollAgentRequest = z.infer<typeof EnrollAgentRequestSchema>;
