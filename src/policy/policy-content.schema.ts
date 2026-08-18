import { z } from 'zod';

/** Same safe slug-like charset `src/authorization/grant-triples.ts`'s `ToolActionSchema` validates `toolId`/`actionId` against — kept as a separate local constant (not imported) since a policy rule's `toolId`/`actionId` additionally allow the wildcard `"*"`, which that schema does not. */
const TOOL_ACTION_ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/;

/**
 * The declarative rule-content schema `Policy`/`PolicyVersion` store
 * (Phase 6, Sections 21-22 — see docs/policy-model.md for the full
 * documented format with worked examples). A small, real format, not a
 * placeholder: an ordered list of rules, each matching by `toolId`/
 * `actionId` (exact string or the wildcard `"*"`, mirroring the wildcard
 * convention `src/authorization/openfga-object-id.util.ts`'s
 * `ANY_RESOURCE_PATTERN` already establishes for resource matching) and
 * optionally `resourcePattern` (same exact-or-`"*"` convention), carrying
 * an `effect` and an optional risk contribution.
 *
 * **First-match-wins within a policy** (Section 21): `PolicyEngine`
 * evaluates `rules` in array order and stops at the first rule whose
 * `toolId`/`actionId`/`resourcePattern` all match the request — order is
 * significant, not just presence. A policy with no matching rule at all
 * contributes no restriction (see `PolicyEngine`'s own doc comment for why
 * that's `ALLOW`/pass-through, never an implicit deny).
 */

export const PolicyEffectSchema = z.enum(['ALLOW', 'DENY', 'REQUIRE_APPROVAL']);
export type PolicyEffect = z.infer<typeof PolicyEffectSchema>;

export const PolicyRuleSchema = z.object({
  /** Human-readable label for this rule — audit/debugging convenience only, never matched against. */
  name: z.string().min(1).max(200).optional(),

  /** Exact `toolId` to match, or the wildcard `"*"` ("any tool"). */
  toolId: z
    .string()
    .min(1)
    .max(128)
    .refine((v) => v === '*' || TOOL_ACTION_ID_PATTERN.test(v), {
      message: 'toolId must be "*" or match the safe slug-like charset',
    }),

  /** Exact `actionId` to match, or the wildcard `"*"` ("any action"). */
  actionId: z
    .string()
    .min(1)
    .max(128)
    .refine((v) => v === '*' || TOOL_ACTION_ID_PATTERN.test(v), {
      message: 'actionId must be "*" or match the safe slug-like charset',
    }),

  /**
   * Exact resource identifier to match, or `"*"` ("any resource for this
   * tool/action") — mirrors `allowedResourceSelectors[].pattern`'s exact-
   * or-wildcard convention (see docs/authorization-model.md's known
   * resource-matching limitation, which applies here too: no glob/prefix
   * matching this phase). Omitted entirely means the same as `"*"`.
   */
  resourcePattern: z.string().min(1).max(2048).default('*'),

  effect: PolicyEffectSchema,

  /**
   * Additive contribution to `RiskEngine`'s deterministic score when this
   * rule is the one that matched (0-100). Optional — a rule with no
   * `riskWeight` contributes nothing beyond the baseline/other signals.
   */
  riskWeight: z.number().min(0).max(100).optional(),

  /**
   * A *minimum* `RiskEngine` will clamp its score up to when this rule
   * matched, regardless of what the additive contributors alone would sum
   * to (e.g. "this action is always at least MEDIUM risk"). Optional.
   */
  riskFloor: z.number().min(0).max(100).optional(),

  /** Free-text rationale for this specific rule — audit/debugging convenience, never evaluated. */
  description: z.string().max(2000).optional(),
});
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

export const PolicyContentSchema = z.object({
  /** First-match-wins, in array order — see module doc comment. */
  rules: z.array(PolicyRuleSchema).min(1).max(200),
});
export type PolicyContent = z.infer<typeof PolicyContentSchema>;

/** Parses+validates arbitrary JSON-shaped input (already-parsed JSON, or a `PolicyVersion.content` JSONB column read back) into a typed `PolicyContent`. Throws (via Zod) on anything malformed — the caller decides fail-open-vs-closed semantics (see `PolicyEngine`, which fails closed). */
export function parsePolicyContent(candidate: unknown): PolicyContent {
  return PolicyContentSchema.parse(candidate);
}
