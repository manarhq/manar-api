import type { PolicyRule } from '../policy/policy-content.schema';

/**
 * "Approve + make rule": a pre-filled ALLOW rule for the rule editor. The resource pattern starts as
 * the exact resource the person just approved; widening it is their choice in the editor. Returns
 * null rather than a wider rule when the resource cannot be used as a pattern.
 */
export function buildRuleDraft(input: {
  toolId: string;
  actionId: string;
  resource: string;
}): Omit<
  PolicyRule,
  'riskWeight' | 'riskFloor' | 'resourceClassification'
> | null {
  // A trailing `*` is a prefix match in the policy engine and `*` is everything: a draft built
  // from such a resource would widen what was approved, so there is no draft.
  if (input.resource.length === 0 || input.resource.length > 2048) return null;
  if (input.resource.endsWith('*')) return null;
  return {
    name: `Allow ${input.toolId} ${input.actionId}`.slice(0, 200),
    toolId: input.toolId,
    actionId: input.actionId,
    resourcePattern: input.resource,
    effect: 'ALLOW',
    description: 'Created from an approval.',
  };
}
