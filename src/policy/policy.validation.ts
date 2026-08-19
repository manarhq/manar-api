import { z } from 'zod';

/**
 * Request-body validation for `/policies` (human-facing policy management),
 * following this codebase's established Zod-first convention — see
 * `src/agents/agents.validation.ts`'s doc comment. Every write accepts
 * *either* JSON `content` *or* a YAML `contentYaml` string — never both —
 * matching Section 21's "GUI/YAML/JSON must manipulate the same underlying
 * model" requirement (see docs/policy-model.md). `content` itself is
 * `z.unknown()` here; the actual `PolicyContentSchema` validation happens
 * once, after resolving whichever of the two the caller submitted (see
 * `src/policy/policy-content-codec.ts`'s `resolveSubmittedContent`), so the same validation/error path
 * is shared by both input formats.
 */

export const CreatePolicyRequestSchema = z
  .object({
    name: z.string().min(1).max(200),
    description: z.string().max(2000).optional(),
    content: z.unknown().optional(),
    contentYaml: z.string().min(1).optional(),
    reason: z.string().min(1).max(500).optional(),
  })
  .refine(
    (body) => (body.content !== undefined) !== (body.contentYaml !== undefined),
    {
      message: 'Exactly one of "content" or "contentYaml" must be provided',
    },
  );
export type CreatePolicyRequest = z.infer<typeof CreatePolicyRequestSchema>;

export const CreatePolicyVersionRequestSchema = z
  .object({
    content: z.unknown().optional(),
    contentYaml: z.string().min(1).optional(),
    rollbackToVersionId: z.string().min(1).optional(),
    reason: z.string().min(1).max(500).optional(),
  })
  .refine(
    (body) =>
      [
        body.content !== undefined,
        body.contentYaml !== undefined,
        body.rollbackToVersionId !== undefined,
      ].filter(Boolean).length === 1,
    {
      message:
        'Exactly one of "content", "contentYaml", or "rollbackToVersionId" must be provided',
    },
  );
export type CreatePolicyVersionRequest = z.infer<
  typeof CreatePolicyVersionRequestSchema
>;

/**
 * `POST /policies/suggest`'s request body (Phase 10c). Exactly one of
 * `policyId` (an existing policy — the draft becomes its next version) or
 * `policyName` (a brand-new policy, created alongside its first draft
 * version) must be provided — same "exactly one" shape
 * `CreatePolicyRequestSchema`/`CreatePolicyVersionRequestSchema` already
 * establish for their own mutually-exclusive content fields.
 */
export const SuggestPolicyRequestSchema = z
  .object({
    naturalLanguageDescription: z.string().min(1).max(5000),
    policyId: z.string().min(1).optional(),
    policyName: z.string().min(1).max(200).optional(),
    policyDescription: z.string().max(2000).optional(),
    reason: z.string().min(1).max(500).optional(),
  })
  .refine(
    (body) => (body.policyId !== undefined) !== (body.policyName !== undefined),
    {
      message: 'Exactly one of "policyId" or "policyName" must be provided',
    },
  );
export type SuggestPolicyRequest = z.infer<typeof SuggestPolicyRequestSchema>;
