import { z } from 'zod';
import {
  GrantableToolActionSchema,
  ResourceSelectorSchema,
  ToolActionSchema,
} from '../authorization/grant-triples';

/**
 * Request-body validation for `/tasks` (human-facing task creation/
 * revocation), following this codebase's established Zod-first convention
 * — see `src/agents/agents.validation.ts`'s doc comment.
 */

export const CreateTaskRequestSchema = z
  .object({
    name: z.string().min(1).max(200),
    description: z.string().max(2000).optional(),
    assignedAgentId: z.string().min(1),
    allowedToolActions: z.array(GrantableToolActionSchema).max(100).default([]),
    allowedResourceSelectors: z
      .array(ResourceSelectorSchema)
      .max(100)
      .default([]),
    forbiddenActions: z.array(ToolActionSchema).max(100).default([]),
    /** Defaults to "now" if omitted. */
    startsAt: z.coerce.date().optional(),
    expiresAt: z.coerce.date(),
    maxExecutions: z.number().int().positive().nullable().optional(),
    /** 0-100, conservative default — see Task.riskCeiling's schema doc comment. */
    riskCeiling: z.number().int().min(0).max(100).default(20),
  })
  .refine((body) => body.expiresAt.getTime() > Date.now(), {
    message: 'expiresAt must be in the future',
    path: ['expiresAt'],
  });
export type CreateTaskRequest = z.infer<typeof CreateTaskRequestSchema>;

export const RevokeTaskRequestSchema = z.object({
  reason: z.string().min(1).max(500),
});
export type RevokeTaskRequest = z.infer<typeof RevokeTaskRequestSchema>;
