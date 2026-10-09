import { z } from 'zod';
import { DataClassificationSchema } from '../common/data-classification';

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

/**
 * Phase 1: the effect vocabulary is `CLAUDE.md` §7's, so `APPROVAL_REQUIRED`,
 * not the `REQUIRE_APPROVAL` this codebase used until now.
 *
 * `REQUIRE_APPROVAL` is accepted as a **deprecated alias on read and
 * normalised away**, never written. It is not a courtesy: `PolicyVersion`
 * rows are immutable and carry a `contentHash` over `content`, so a data
 * migration that rewrote the stored spelling would invalidate every hash it
 * touched. Reading the old spelling and normalising it keeps those rows
 * verifiable *and* keeps the evaluator on one vocabulary.
 *
 * Remove the alias once no `PolicyVersion` row predating this change
 * survives retention.
 */
export const PolicyEffectSchema = z
  .enum(['ALLOW', 'DENY', 'APPROVAL_REQUIRED', 'REQUIRE_APPROVAL'])
  .transform((effect) =>
    effect === 'REQUIRE_APPROVAL' ? ('APPROVAL_REQUIRED' as const) : effect,
  );
export type PolicyEffect = 'ALLOW' | 'DENY' | 'APPROVAL_REQUIRED';

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
   * Exact resource identifier to match, `"*"` ("any resource for this
   * tool/action"), or a prefix ending in `*` (`manar/demo-repo:*`, ADR-0011;
   * see `resourcePatternMatches`). Task `allowedResourceSelectors` stay
   * exact-or-`"*"`. Omitted entirely means the same as `"*"`.
   */
  resourcePattern: z.string().min(1).max(2048).default('*'),

  /**
   * Phase 15a (Section 53) — an optional additional match condition: when
   * present, this rule only matches a request whose resolved
   * `ToolAction.classification` (looked up by `PolicyEngine.evaluate` the
   * same way it already resolves everything else about the request —
   * `ToolRegistryService.findToolAction`) equals this value exactly. A
   * request whose `{toolId, actionId}` doesn't resolve to any registered
   * `ToolAction` at all has no known classification, so a rule carrying
   * `resourceClassification` never matches it (the same "not registered is
   * not a match" posture `RiskEngine` already established for its own
   * `ToolAction` lookup — see docs/data-classification.md). Omitted means
   * "match regardless of classification," identical to this field's
   * absence today.
   */
  resourceClassification: DataClassificationSchema.optional(),

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
