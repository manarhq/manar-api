import { z } from 'zod';

/**
 * Request-body validation for `POST /evidence/export` (Section 49). At
 * least one filter dimension is required (`.refine` below) — an
 * unqualified "export the entire tenant chain" isn't this endpoint's job,
 * and unbounded export bodies aren't a scale this phase targets.
 */
export const EvidenceExportRequestSchema = z
  .object({
    since: z.coerce.date().optional(),
    until: z.coerce.date().optional(),
    agentId: z.string().min(1).optional(),
    taskId: z.string().min(1).optional(),
    correlationId: z.string().min(1).optional(),
  })
  .refine(
    (body) =>
      body.since !== undefined ||
      body.until !== undefined ||
      body.agentId !== undefined ||
      body.taskId !== undefined ||
      body.correlationId !== undefined,
    {
      message:
        'At least one filter (since, until, agentId, taskId, or correlationId) is required',
    },
  )
  .refine(
    (body) =>
      !body.since ||
      !body.until ||
      body.until.getTime() >= body.since.getTime(),
    { message: 'until must not be before since', path: ['until'] },
  );

export type EvidenceExportRequest = z.infer<typeof EvidenceExportRequestSchema>;

/** `POST /evidence/verify`: an exported bundle and its signature, as `POST /evidence/export` returned them. */
export const EvidenceVerifyRequestSchema = z.object({
  bundle: z
    .unknown()
    .refine((value) => value !== undefined, 'bundle is required'),
  signature: z.string().min(1),
});
