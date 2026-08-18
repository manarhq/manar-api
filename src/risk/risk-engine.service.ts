import { Injectable } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { TaskRecord, TasksService } from '../tasks/tasks.service';
import type { PolicyRule } from '../policy/policy-content.schema';

export interface RiskScoreInput {
  toolId: string;
  actionId: string;
  resource: string;
  task: TaskRecord;
  /** The rule `PolicyEngine.evaluate` matched for this same request, if any — reused here rather than re-evaluated (see docs/policy-model.md). */
  policyMatch?: Pick<PolicyRule, 'riskWeight' | 'riskFloor'>;
}

export interface RiskScoreResult {
  deterministicRiskScore: number;
  /** Phase 10 (AI advisory risk scoring) — always `null` this phase. */
  aiAdvisoryScore: null;
  /** Equals `deterministicRiskScore` this phase (there is no AI advisory score yet to combine it with). */
  finalRiskScore: number;
  reasonCodes: string[];
}

const MIN_SCORE = 0;
const MAX_SCORE = 100;
const BASELINE_SCORE = 10;
const DELEGATION_DEPTH_POINTS_PER_HOP = 5;
const DELEGATION_DEPTH_CAP = 30;
const DESTRUCTIVE_KEYWORD_POINTS = 25;

/**
 * A crude, **explicitly temporary** placeholder for Phase 7's real
 * `ToolAction.mutating`/`destructive` flags (there is no Tool Registry
 * yet) — plain substring matching against an opaque, caller-supplied
 * `actionId`, nothing more. Meant to be deleted, not extended, once Phase
 * 7 ships real per-action risk metadata. See docs/policy-model.md.
 */
const DESTRUCTIVE_KEYWORDS = [
  'delete',
  'disable',
  'isolate',
  'block',
  'revoke',
  'terminate',
  'kill',
  'remove',
  'destroy',
];

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

/**
 * Sections 21-26's numeric (0-100) risk engine. `AuthorizationService`
 * calls `score` after `PolicyEngine.evaluate` (same request), immediately
 * before deciding `ALLOW` vs. `REQUIRE_APPROVAL` against `task.riskCeiling`
 * (Phase 5's field, unused until this phase). This phase's inputs are
 * necessarily limited — there is no Tool Registry yet (Phase 7, which will
 * add `ToolAction.riskBaseScore`/`mutating`/`destructive` as a *real*
 * input; this does not fake one). `finalRiskScore` equals
 * `deterministicRiskScore` this phase — `aiAdvisoryScore` (Phase 10) stays
 * `null`.
 *
 * Every contributor is recorded in `reasonCodes`, in the order applied, so
 * a score is always explainable from the response alone — see
 * docs/policy-model.md for the full list of contributors and their exact
 * point values.
 */
@Injectable()
export class RiskEngine {
  constructor(private readonly tasksService: TasksService) {}

  async score(
    tenantClient: TenantPrismaClient,
    input: RiskScoreInput,
  ): Promise<RiskScoreResult> {
    const reasonCodes: string[] = [];
    let sum = BASELINE_SCORE;
    reasonCodes.push(`baseline_risk:${BASELINE_SCORE}`);

    // Delegation depth: reuses Phase 5's own ancestor-chain walk
    // (TasksService.getAncestorChain) rather than re-deriving it.
    const ancestors = await this.tasksService.getAncestorChain(
      tenantClient,
      input.task,
    );
    if (ancestors.length > 0) {
      const depthPoints = Math.min(
        ancestors.length * DELEGATION_DEPTH_POINTS_PER_HOP,
        DELEGATION_DEPTH_CAP,
      );
      sum += depthPoints;
      reasonCodes.push(`delegation_depth:${ancestors.length}:${depthPoints}`);
    }

    const destructiveKeyword = DESTRUCTIVE_KEYWORDS.find((keyword) =>
      input.actionId.toLowerCase().includes(keyword),
    );
    if (destructiveKeyword) {
      sum += DESTRUCTIVE_KEYWORD_POINTS;
      reasonCodes.push(`destructive_keyword:${destructiveKeyword}`);
    }

    if (input.policyMatch?.riskWeight != null) {
      sum += input.policyMatch.riskWeight;
      reasonCodes.push(`policy_risk_weight:${input.policyMatch.riskWeight}`);
    }

    let deterministicRiskScore = clamp(sum, MIN_SCORE, MAX_SCORE);

    if (input.policyMatch?.riskFloor != null) {
      const floored = Math.max(
        deterministicRiskScore,
        input.policyMatch.riskFloor,
      );
      if (floored !== deterministicRiskScore) {
        reasonCodes.push(`policy_risk_floor:${input.policyMatch.riskFloor}`);
      }
      deterministicRiskScore = clamp(floored, MIN_SCORE, MAX_SCORE);
    }

    return {
      deterministicRiskScore,
      aiAdvisoryScore: null,
      finalRiskScore: deterministicRiskScore,
      reasonCodes,
    };
  }
}
