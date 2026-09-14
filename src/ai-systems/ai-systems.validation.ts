import { z } from 'zod';

/**
 * Release 2026-11-11 (brief §3.1) — request-body schemas for
 * `/ai-systems`. Same convention as `incidents.validation.ts`: zod at the
 * edge via `parseBodyOrThrow`, with the DTO classes in `ai-systems.dto.ts`
 * existing only to describe the same shape to Swagger.
 */

export const AI_SYSTEM_LIFECYCLE_STATES = [
  'DRAFT',
  'REVIEW',
  'ACTIVE',
  'SUSPENDED',
  'RETIRED',
] as const;

export const AI_SYSTEM_ENVIRONMENTS = [
  'DEVELOPMENT',
  'STAGING',
  'PRODUCTION',
] as const;

export const DATA_CLASSIFICATIONS = [
  'PUBLIC',
  'INTERNAL',
  'CONFIDENTIAL',
  'RESTRICTED',
] as const;

/**
 * `AiSystem.slug` — lowercase kebab, the same shape `Agent.slug` uses.
 * Immutable after creation (there is deliberately no `slug` field on the
 * update schema): it appears in shared deep links and in exported evidence
 * bundles, and a mutable identifier there turns a citation into a dangling
 * reference.
 */
const SlugSchema = z
  .string()
  .min(2)
  .max(64)
  .regex(
    /^[a-z0-9]+(?:-[a-z0-9]+)*$/,
    'Must be lowercase alphanumeric segments separated by single hyphens',
  );

/**
 * An ISO-8601 date-time the caller supplies for `nextReviewDate`. Accepted
 * as a string and converted here rather than trusting `new Date(...)` on
 * arbitrary input downstream — an unparseable value must be a 400, never
 * an `Invalid Date` silently written to the column.
 */
const ReviewDateSchema = z
  .string()
  .datetime({ offset: true })
  .transform((value) => new Date(value));

/** `POST /ai-systems`. Creates in `DRAFT` — a new record is never born ACTIVE, see `AiSystemsService.createAiSystem`. */
export const CreateAiSystemSchema = z.object({
  slug: SlugSchema,
  name: z.string().min(1).max(200),
  businessPurpose: z.string().min(1).max(2000),
  /** A `UserProfile.id` in this tenant. Verified to exist before the row is written. */
  ownerId: z.string().min(1),
  businessUnit: z.string().min(1).max(200),
  environment: z.enum(AI_SYSTEM_ENVIRONMENTS),
  dataClassification: z.enum(DATA_CLASSIFICATIONS).optional(),
  declaredProvider: z.string().min(1).max(100).optional(),
  declaredModel: z.string().min(1).max(200).optional(),
  riskRationale: z.string().min(1).max(4000),
  nextReviewDate: ReviewDateSchema.optional(),
});
export type CreateAiSystemRequest = z.infer<typeof CreateAiSystemSchema>;

/**
 * `PATCH /ai-systems/:id`. Every field here is *material* — changing any
 * of them snapshots the prior state into `AiSystemVersion` and increments
 * `AiSystem.version`, which is why `changeReason` is required rather than
 * optional. `lifecycleState` is deliberately absent: state moves through
 * `POST /ai-systems/:id/transitions` only, so the allowed-edge table and
 * the separation-of-duties rule cannot be bypassed by a plain field
 * update.
 */
export const UpdateAiSystemSchema = z
  .object({
    name: z.string().min(1).max(200).optional(),
    businessPurpose: z.string().min(1).max(2000).optional(),
    ownerId: z.string().min(1).optional(),
    businessUnit: z.string().min(1).max(200).optional(),
    environment: z.enum(AI_SYSTEM_ENVIRONMENTS).optional(),
    dataClassification: z.enum(DATA_CLASSIFICATIONS).optional(),
    /** Explicit `null` clears the declaration; omitting the key leaves it unchanged. */
    declaredProvider: z.string().min(1).max(100).nullable().optional(),
    declaredModel: z.string().min(1).max(200).nullable().optional(),
    riskRationale: z.string().min(1).max(4000).optional(),
    nextReviewDate: ReviewDateSchema.nullable().optional(),
    changeReason: z.string().min(1).max(1000),
  })
  .refine(
    (value) =>
      Object.keys(value).filter((key) => key !== 'changeReason').length > 0,
    {
      message: 'At least one field besides "changeReason" must be provided',
    },
  );
export type UpdateAiSystemRequest = z.infer<typeof UpdateAiSystemSchema>;

/** `POST /ai-systems/:id/transitions` — the only way `lifecycleState` ever changes. */
export const TransitionAiSystemSchema = z.object({
  toState: z.enum(AI_SYSTEM_LIFECYCLE_STATES),
  /** Required. A lifecycle change with no stated reason is not evidence of a decision. */
  reason: z.string().min(1).max(1000),
});
export type TransitionAiSystemRequest = z.infer<
  typeof TransitionAiSystemSchema
>;

/** `POST /ai-systems/:id/agents` — link an existing agent. Additive; never rewrites the agent. */
export const LinkAgentSchema = z.object({
  agentId: z.string().min(1),
});
export type LinkAgentRequest = z.infer<typeof LinkAgentSchema>;

/** `POST /ai-systems/:id/tools` — link a registered tool. */
export const LinkToolSchema = z.object({
  toolId: z.string().min(1),
});
export type LinkToolRequest = z.infer<typeof LinkToolSchema>;
