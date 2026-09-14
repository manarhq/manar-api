import { Injectable, Logger } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { ToolRegistryService } from '../tools/tool-registry.service';
import type { DataClassification } from '../common/data-classification';
import {
  PolicyContentSchema,
  PolicyEffect,
  PolicyRule,
} from './policy-content.schema';

export interface PolicyEvaluationRequest {
  toolId: string;
  actionId: string;
  resource: string;
}

export interface PolicyEvaluationResult {
  effect: PolicyEffect;
  /** The rule that determined `effect` — present whenever some policy's rule actually matched (i.e. `effect` didn't fall through to the pass-through default). */
  matchedRule?: PolicyRule;
  /** Which `Policy` `matchedRule` came from — present under the same condition as `matchedRule`. */
  policyId?: string;
  policyVersionId?: string;
  /** Present only when `effect` is `DENY` because evaluation itself failed (Section 22's real fail-closed case) rather than because a rule's own effect was `DENY` — see module doc comment. */
  failureReason?: string;
}

const EFFECT_RANK: Record<PolicyEffect, number> = {
  ALLOW: 0,
  APPROVAL_REQUIRED: 1,
  DENY: 2,
};

/**
 * Sections 21-22 — the deterministic, versioned policy layer on top of
 * Phase 5's OpenFGA task-scope check (docs/authorization-model.md).
 * `AuthorizationService` calls `evaluate` after its own OpenFGA `check()`
 * already succeeded — this engine does NOT re-decide whether the action is
 * permitted at all, it only adds extra, org-defined restrictions on top of
 * an already-permitted action.
 *
 * **`ALLOW` (pass-through) is the normal, fully-evaluated outcome when no
 * policy rule matches** — not a fallback, and never conflated with a
 * failure. The *actual* fail-closed case (Section 22) is a genuine
 * failure to evaluate: a database error loading `PolicyVersion` rows, or
 * stored `content` that fails `PolicyContentSchema` validation (evidence
 * of data corruption or a bypassed write path — see docs/policy-model.md)
 * — either of those denies the *entire* request, logged clearly, distinct
 * from "every published policy was consulted and none of them restricted
 * this."
 */
@Injectable()
export class PolicyEngine {
  private readonly logger = new Logger(PolicyEngine.name);

  /**
   * Phase 15a (Section 53): resolving `resourceClassification` matches
   * needs `ToolRegistryService` — the exact same dependency `RiskEngine`
   * already carries for its own `ToolAction` lookup (see that class's doc
   * comment: "gained a `ToolRegistryService` constructor parameter" is not
   * a new pattern in this codebase — existing direct-construction test
   * call sites are updated to pass one, same as that phase).
   */
  constructor(private readonly toolRegistry: ToolRegistryService) {}

  async evaluate(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    request: PolicyEvaluationRequest,
  ): Promise<PolicyEvaluationResult> {
    let publishedVersions: Awaited<
      ReturnType<typeof this.loadLatestPublishedVersions>
    >;
    try {
      publishedVersions = await this.loadLatestPublishedVersions(tenantClient);
    } catch (error) {
      this.logger.error(
        `Failed to load published policy versions for tenant "${tenantId}" — failing closed (DENY)`,
        error instanceof Error ? error.stack : undefined,
      );
      return {
        effect: 'DENY',
        failureReason: 'policy_load_failed',
      };
    }

    // Phase 15a (Section 53): resolved once per `evaluate` call, not per
    // rule/policy — `undefined` (no registered `ToolAction` for this
    // {toolId, actionId} pair) means a rule carrying `resourceClassification`
    // never matches this request, the same "not registered is not a match"
    // posture `RiskEngine` already established for the identical lookup.
    let classification: DataClassification | undefined;
    try {
      const registered = await this.toolRegistry.findToolAction(
        tenantClient,
        request.toolId,
        request.actionId,
      );
      classification = registered?.action.classification;
    } catch (error) {
      this.logger.warn(
        `Could not resolve ToolAction classification for tenant "${tenantId}" ("${request.toolId}"/"${request.actionId}") — proceeding as if unclassified (no ToolAction-classification rule can match): ${error instanceof Error ? error.message : String(error)}`,
      );
      classification = undefined;
    }

    let best: PolicyEvaluationResult = { effect: 'ALLOW' };

    for (const version of publishedVersions) {
      const parsed = PolicyContentSchema.safeParse(version.content);
      if (!parsed.success) {
        this.logger.error(
          `Policy "${version.policyId}" version "${version.id}" has content that fails PolicyContentSchema validation for tenant "${tenantId}" — failing closed (DENY): ${parsed.error.message}`,
        );
        return {
          effect: 'DENY',
          failureReason: 'policy_content_invalid',
        };
      }

      const matched = matchFirstRule(
        parsed.data.rules,
        request,
        classification,
      );
      if (!matched) continue;

      const candidate: PolicyEvaluationResult = {
        effect: matched.effect,
        matchedRule: matched,
        policyId: version.policyId,
        policyVersionId: version.id,
      };
      // The very first policy that actually matches anything becomes
      // `best` outright (even an ALLOW rule is more informative than the
      // untouched "nothing matched yet" default); after that, only a
      // strictly more restrictive effect from another policy overrides it
      // (most-restrictive-wins).
      if (
        !best.policyId ||
        EFFECT_RANK[candidate.effect] > EFFECT_RANK[best.effect]
      ) {
        best = candidate;
      }
    }

    return best;
  }

  /**
   * One `PolicyVersion` per `Policy` — the highest-`version` row whose
   * `status` is `PUBLISHED` (never a `DRAFT`, regardless of how recent).
   * Structural tenant isolation (Phase 2 — `tenantClient` is already the
   * correct tenant's own database) means no `tenantId` filter is needed in
   * the query itself, matching every other service in this codebase (e.g.
   * `TasksService`).
   */
  private async loadLatestPublishedVersions(tenantClient: TenantPrismaClient) {
    const rows = await tenantClient.policyVersion.findMany({
      where: { status: 'PUBLISHED' },
      orderBy: [{ policyId: 'asc' }, { version: 'desc' }],
    });

    const latestByPolicy = new Map<string, (typeof rows)[number]>();
    for (const row of rows) {
      if (!latestByPolicy.has(row.policyId)) {
        latestByPolicy.set(row.policyId, row);
      }
    }
    return [...latestByPolicy.values()];
  }
}

/** First-match-wins within a single policy's rule list (Section 21) — see docs/policy-model.md. */
function matchFirstRule(
  rules: readonly PolicyRule[],
  request: PolicyEvaluationRequest,
  classification: DataClassification | undefined,
): PolicyRule | undefined {
  return rules.find((rule) => ruleMatches(rule, request, classification));
}

function ruleMatches(
  rule: PolicyRule,
  request: PolicyEvaluationRequest,
  classification: DataClassification | undefined,
): boolean {
  const toolMatches = rule.toolId === '*' || rule.toolId === request.toolId;
  const actionMatches =
    rule.actionId === '*' || rule.actionId === request.actionId;
  const resourceMatches =
    rule.resourcePattern === '*' || rule.resourcePattern === request.resource;
  // Phase 15a (Section 53): absent means "match regardless of
  // classification" (identical to before this field existed); present
  // means an exact match against the resolved ToolAction's classification,
  // which is `undefined` for an unregistered {toolId, actionId} — see
  // `PolicyRuleSchema.resourceClassification`'s doc comment.
  const classificationMatches =
    rule.resourceClassification === undefined ||
    rule.resourceClassification === classification;
  return (
    toolMatches && actionMatches && resourceMatches && classificationMatches
  );
}
