import { z } from 'zod';

/**
 * `POST /audit/investigate`'s request body (Phase 10c) — the JSON-body
 * counterpart to `GET /audit`'s query-param filters (`AuditController.search`
 * parses those by hand since query params are always strings; a JSON body
 * can carry real types directly, so this schema validates them as such
 * rather than re-stringifying). Same filter set (Section 66), reused as-is
 * — see `AuditSearchService`'s doc comment for why `tenantId` is
 * deliberately not one of these fields.
 */
export const InvestigateAuditSchema = z.object({
  question: z.string().min(1).max(2000),
  eventType: z.string().min(1).optional(),
  correlationId: z.string().min(1).optional(),
  agentId: z.string().min(1).optional(),
  taskId: z.string().min(1).optional(),
  toolId: z.string().min(1).optional(),
  actionId: z.string().min(1).optional(),
  decision: z.string().min(1).optional(),
  riskMin: z.number().int().min(0).max(100).optional(),
  riskMax: z.number().int().min(0).max(100).optional(),
  from: z.string().min(1).optional(),
  to: z.string().min(1).optional(),
  contextLimit: z.number().int().positive().max(50).optional(),
});
export type InvestigateAuditRequest = z.infer<typeof InvestigateAuditSchema>;
