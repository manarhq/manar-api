import { z } from 'zod';

/**
 * `POST /approvals/:id/decide`'s request body — see docs/approvals.md. The console sends
 * `approve_once | approve_8h | deny`; the older `APPROVE | DENY` still work and mean
 * approve_once and deny. `makeRule` asks for a pre-filled policy rule in the response.
 */
export const DecideApprovalRequestSchema = z
  .object({
    decision: z.enum(['approve_once', 'approve_8h', 'deny', 'APPROVE', 'DENY']),
    reason: z.string().max(1000).optional(),
    makeRule: z.boolean().optional(),
  })
  .transform((v) => ({
    /** What the workflow is signalled with. */
    decision:
      v.decision === 'deny' || v.decision === 'DENY'
        ? ('DENY' as const)
        : ('APPROVE' as const),
    /** Create an 8-hour allow grant after the approval took effect. */
    extended: v.decision === 'approve_8h',
    reason: v.reason,
    makeRule: v.makeRule === true,
  }));
export type DecideApprovalRequest = z.output<
  typeof DecideApprovalRequestSchema
>;

/** Used by the device decide endpoint and the host-approval console routes. */
export const DecideHostApprovalSchema = z.object({
  decision: z.enum(['approve_once', 'approve_8h', 'deny']),
  makeRule: z.boolean().optional(),
});
