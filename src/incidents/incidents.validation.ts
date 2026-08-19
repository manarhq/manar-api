import { z } from 'zod';

const INCIDENT_SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
const INCIDENT_STATUSES = [
  'OPEN',
  'INVESTIGATING',
  'RESOLVED',
  'CLOSED',
] as const;

/** A `Json`-array-of-correlation-ID-strings — see `Incident.relatedCorrelationIds`'s doc comment (`prisma/tenant.prisma`): a plain, human-curated reference list into `AuditEvent.correlationId`, never validated against real rows (an incident may reasonably be created before every related event is even known, and correlation IDs are UUIDs but this schema doesn't enforce that shape elsewhere either — see `EvidenceExportService`'s identical posture toward `correlationId` filters). */
const RelatedCorrelationIdsSchema = z.array(z.string().min(1)).max(200);

/** `POST /incidents`'s request body. */
export const CreateIncidentSchema = z.object({
  title: z.string().min(1).max(200),
  description: z.string().min(1).max(5000),
  severity: z.enum(INCIDENT_SEVERITIES),
  relatedCorrelationIds: RelatedCorrelationIdsSchema.optional(),
});
export type CreateIncidentRequest = z.infer<typeof CreateIncidentSchema>;

/**
 * `PATCH /incidents/:id`'s request body — a partial update, but at least
 * one field must be present (mirrors `UpdateTenantSettingsSchema`'s
 * identical "an empty PATCH is almost certainly a caller bug" posture).
 * `status`/`relatedCorrelationIds` cover Section 70's "status transitions,
 * resolution notes" requirement together: a status transition is a plain
 * `status` change, and resolution notes are captured by also updating
 * `description` in the same call (there is no separate `resolutionNotes`
 * column on `Incident` — see that model's doc comment for its exact,
 * deliberately minimal field list).
 */
export const UpdateIncidentSchema = z
  .object({
    title: z.string().min(1).max(200).optional(),
    description: z.string().min(1).max(5000).optional(),
    severity: z.enum(INCIDENT_SEVERITIES).optional(),
    status: z.enum(INCIDENT_STATUSES).optional(),
    relatedCorrelationIds: RelatedCorrelationIdsSchema.optional(),
  })
  .refine((value) => Object.keys(value).length > 0, {
    message: 'At least one field must be provided',
  });
export type UpdateIncidentRequest = z.infer<typeof UpdateIncidentSchema>;
