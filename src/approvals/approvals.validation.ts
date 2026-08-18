import { z } from 'zod';

/** `POST /approvals/:id/decide`'s request body — see docs/approvals.md. */
export const DecideApprovalRequestSchema = z.object({
  decision: z.enum(['APPROVE', 'DENY']),
  reason: z.string().max(1000).optional(),
});
export type DecideApprovalRequest = z.infer<typeof DecideApprovalRequestSchema>;
