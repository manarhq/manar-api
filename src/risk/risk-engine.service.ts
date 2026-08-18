import { Injectable } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { TaskRecord, TasksService } from '../tasks/tasks.service';
import type { PolicyRule } from '../policy/policy-content.schema';
import { ToolRegistryService } from '../tools/tool-registry.service';

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
/** Additive contribution when the resolved `ToolAction.mutating` flag is `true`. */
const MUTATING_POINTS = 15;
/** Additive contribution when the resolved `ToolAction.destructive` flag is `true` — on top of, not instead of, `MUTATING_POINTS` (every destructive action is mutating too, but the two flags are independent booleans on the schema, so both contribute independently). */
const DESTRUCTIVE_POINTS = 25;

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

/**
 * Sections 21-26's numeric (0-100) risk engine. `AuthorizationService`
 * calls `score` after `PolicyEngine.evaluate` (same request), immediately
 * before deciding `ALLOW` vs. `REQUIRE_APPROVAL` against `task.riskCeiling`
 * (Phase 5's field, unused until this phase). This phase's inputs are
 * necessarily limited this phase — since Phase 7b, `ToolRegistryService`
 * resolves `{ toolId, actionId }` against a real registered `ToolAction`
 * when one exists (`riskBaseScore`/`mutating`/`destructive` — real,
 * operator-declared per-action risk metadata, replacing the placeholder
 * keyword heuristic Phase 6 shipped and explicitly documented as
 * temporary — see git history for that deleted code). When no such
 * `ToolAction` is registered (an opaque `toolId`/`actionId` pair that
 * predates this phase's registry, or simply hasn't been registered yet —
 * still the overwhelming majority of Phase 5/6's own pre-existing tests),
 * this contributes nothing at all, rather than guessing — exactly like
 * `PolicyEngine`'s "no rule matched" case, "not registered" is a normal
 * outcome, never conflated with a failure. `finalRiskScore` equals
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
  constructor(
    private readonly tasksService: TasksService,
    private readonly toolRegistry: ToolRegistryService,
  ) {}

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

    // Real per-action risk metadata (Phase 7b), replacing Phase 6's
    // deleted destructive-keyword heuristic. `null` (no registered
    // ToolAction for this {toolId, actionId} pair) contributes nothing —
    // see class doc comment.
    const registered = await this.toolRegistry.findToolAction(
      tenantClient,
      input.toolId,
      input.actionId,
    );
    if (registered) {
      const { action } = registered;
      sum += action.riskBaseScore;
      reasonCodes.push(`tool_action_risk_base:${action.riskBaseScore}`);
      if (action.mutating) {
        sum += MUTATING_POINTS;
        reasonCodes.push(`tool_action_mutating:${MUTATING_POINTS}`);
      }
      if (action.destructive) {
        sum += DESTRUCTIVE_POINTS;
        reasonCodes.push(`tool_action_destructive:${DESTRUCTIVE_POINTS}`);
      }
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
