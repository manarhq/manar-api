import { z } from 'zod';
import {
  ResourceSelectorSchema,
  ToolActionSchema,
} from '../authorization/grant-triples';

const SLUG_PATTERN = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;

/**
 * `POST /agent/v1/tasks/:id/delegate` request body — "a subset request"
 * per the design spec: the child task's desired grants (verified as a
 * subset of the parent's *effective* grants — see
 * `DelegationService.delegate`) and a slug for the new child agent. Every
 * other Task field this endpoint also needs a value for
 * (name/description/expiresAt/maxExecutions/riskCeiling) is accepted
 * optionally too — the spec doesn't name these explicitly, but a Task row
 * needs them regardless (`expiresAt` is `NOT NULL`); see
 * docs/task-delegation.md for the defaults/clamping this endpoint applies
 * when they're omitted.
 */
export const DelegateTaskRequestSchema = z.object({
  childAgentSlug: z
    .string()
    .min(1)
    .max(63)
    .regex(SLUG_PATTERN, 'slug must be lowercase alphanumeric with hyphens'),
  childAgentDisplayName: z.string().min(1).max(200).optional(),
  name: z.string().min(1).max(200),
  description: z.string().max(2000).optional(),
  allowedToolActions: z.array(ToolActionSchema).max(100).default([]),
  allowedResourceSelectors: z
    .array(ResourceSelectorSchema)
    .max(100)
    .default([]),
  forbiddenActions: z.array(ToolActionSchema).max(100).default([]),
  /** Clamped to the parent task's own `expiresAt` if omitted or later — see docs/task-delegation.md. */
  expiresAt: z.coerce.date().optional(),
  maxExecutions: z.number().int().positive().nullable().optional(),
  riskCeiling: z.number().int().min(0).max(100).optional(),
});
export type DelegateTaskRequest = z.infer<typeof DelegateTaskRequestSchema>;
