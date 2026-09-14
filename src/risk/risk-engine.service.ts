import { Injectable } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { TaskRecord, TasksService } from '../tasks/tasks.service';
import type { PolicyRule } from '../policy/policy-content.schema';
import { ToolRegistryService } from '../tools/tool-registry.service';
import { AiAdvisoryClient } from '../ai-advisory/ai-advisory-client.service';
import type { DataClassification } from '../common/data-classification';

export interface RiskScoreInput {
  /** Phase 12a: needed to pass through to `AiAdvisoryClient.analyzeRisk`'s data-residency (`allowExternalAi`) check — see docs/ai-security-model.md's "Data residency enforcement" section. */
  tenantId: string;
  toolId: string;
  actionId: string;
  resource: string;
  task: TaskRecord;
  /** The requesting agent — Phase 10b needs this for the `AgentRiskFlag` lookup and to give `AiAdvisoryClient.analyzeRisk` a stable correlation subject; earlier phases only ever threaded `task.assignedAgentId` implicitly via `task` itself. */
  agentId: string;
  /** The rule `PolicyEngine.evaluate` matched for this same request, if any — reused here rather than re-evaluated (see docs/policy-model.md). */
  policyMatch?: Pick<PolicyRule, 'riskWeight' | 'riskFloor'>;
}

export interface RiskScoreResult {
  deterministicRiskScore: number;
  /** Phase 10b: `AiAdvisoryClient.analyzeRisk`'s score (0-100) when a real advisory signal was available, `null` when it was not (unreachable/timed out/circuit open/zero-confidence fail-secure marker — see that class's doc comment). */
  aiAdvisoryScore: number | null;
  /** `max(deterministicRiskScore, aiAdvisoryScore ?? 0)` — see class doc comment for why this is the mechanism that lets AI only ever add restriction, never remove it. */
  finalRiskScore: number;
  /** Deterministic and AI-attributed contributors, in the order applied. AI-derived codes are always prefixed `ai_advisory_*`, kept clearly distinct from deterministic ones — never blended into one anonymous list. */
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
/**
 * Phase 15a (Section 53): additive contribution keyed by the resolved
 * `ToolAction.classification` — a higher-sensitivity action is
 * marginally higher baseline risk, independent of anything `mutating`/
 * `destructive` already contribute (a read-only action against RESTRICTED
 * data is still more sensitive than the identical read against PUBLIC
 * data). `PUBLIC`/`INTERNAL` contribute nothing beyond the flat
 * `BASELINE_SCORE` every request already gets — `INTERNAL` is the schema
 * default, so this must not visibly move an unclassified-in-practice
 * action's score. `CONFIDENTIAL`/`RESTRICTED` step up meaningfully but
 * deliberately not enough alone to force `APPROVAL_REQUIRED` for every
 * such action — that's what a `resourceClassification` policy rule
 * (`docs/policy-model.md`) is for, via its own `riskWeight`/`riskFloor`.
 */
const CLASSIFICATION_RISK_POINTS: Record<DataClassification, number> = {
  PUBLIC: 0,
  INTERNAL: 0,
  CONFIDENTIAL: 10,
  RESTRICTED: 25,
};
/**
 * Phase 10b: fixed additive contribution applied to `deterministicRiskScore`
 * (not `aiAdvisoryScore`) when the requesting agent has an active,
 * unexpired `AgentRiskFlag` row (set by `CredentialBrokerService` on a
 * detected prompt-injection attempt — see docs/ai-security-model.md). A
 * plain DB lookup, deliberately not another AI call — this is what makes a
 * flagged agent's *subsequent* requests measurably higher-risk without
 * ever trusting or re-running anything from the injected content itself
 * (Section 72 — the actual security boundary stays deterministic task
 * scope). Chosen to be large enough to visibly move a request from ALLOW
 * toward `APPROVAL_REQUIRED` territory on its own for a moderately-risky
 * action, without alone guaranteeing it for every action (it is not the
 * full 100-point range) — see docs/ai-security-model.md for the worked
 * example.
 */
const AGENT_RISK_FLAG_BUMP = 20;

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

/**
 * Sections 21-26's numeric (0-100) risk engine. `AuthorizationService`
 * calls `score` after `PolicyEngine.evaluate` (same request), immediately
 * before deciding `ALLOW` vs. `APPROVAL_REQUIRED` against `task.riskCeiling`
 * (Phase 5's field). Since Phase 7b, `ToolRegistryService` resolves
 * `{ toolId, actionId }` against a real registered `ToolAction` when one
 * exists (`riskBaseScore`/`mutating`/`destructive`); when none is
 * registered, this contributes nothing at all, rather than guessing —
 * exactly like `PolicyEngine`'s "no rule matched" case, "not registered" is
 * a normal outcome, never conflated with a failure.
 *
 * Since Phase 10b, two additional deterministic contributors feed
 * `deterministicRiskScore` before it's clamped/floored: `AgentRiskFlag`
 * (see `AGENT_RISK_FLAG_BUMP`'s doc comment), and — layered strictly on
 * top, never blended into the deterministic sum itself —
 * `AiAdvisoryClient.analyzeRisk`'s advisory `aiAdvisoryScore`.
 * `finalRiskScore = max(deterministicRiskScore, aiAdvisoryScore ?? 0)`:
 * this is the concrete mechanism satisfying the non-negotiable "AI can only
 * ever add restriction, never remove it" invariant (Section 26) — AI can
 * push a request's final score *up* past what the deterministic rules
 * alone produced (e.g. into `APPROVAL_REQUIRED` territory), but can never
 * pull it down below the deterministic floor, and a `manar-ai` outage
 * (`aiAdvisoryScore` stays `null`) leaves `finalRiskScore` exactly equal to
 * `deterministicRiskScore` — identical to this engine's behavior before
 * Phase 10 existed (Section 80's mandatory "AI outage does not create
 * fail-open authorization" invariant, extended to risk scoring).
 *
 * Every contributor is recorded in `reasonCodes`, in the order applied, so
 * a score is always explainable from the response alone — see
 * docs/policy-model.md for the deterministic contributors and
 * docs/ai-security-model.md for the AI-advisory combination rule and the
 * `AgentRiskFlag` mechanism.
 *
 * Since Phase 15a (Section 53), the resolved `ToolAction.classification`
 * (when one is registered) is one more deterministic contributor
 * (`CLASSIFICATION_RISK_POINTS`, see its own doc comment) — see
 * docs/data-classification.md.
 */
@Injectable()
export class RiskEngine {
  constructor(
    private readonly tasksService: TasksService,
    private readonly toolRegistry: ToolRegistryService,
    private readonly aiAdvisoryClient: AiAdvisoryClient,
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
      // Phase 15a (Section 53) — see CLASSIFICATION_RISK_POINTS's doc
      // comment. Always recorded when a ToolAction is registered (even a
      // 0-point PUBLIC/INTERNAL contribution), mirroring
      // tool_action_risk_base's identical "always recorded when
      // registered, regardless of value" posture.
      const classificationPoints =
        CLASSIFICATION_RISK_POINTS[action.classification];
      sum += classificationPoints;
      reasonCodes.push(
        `tool_action_classification:${action.classification}:${classificationPoints}`,
      );
    }

    // Phase 10b: a simple DB lookup, never another AI call — see
    // AGENT_RISK_FLAG_BUMP's doc comment.
    const activeFlag = await tenantClient.agentRiskFlag.findFirst({
      where: { agentId: input.agentId, expiresAt: { gt: new Date() } },
      orderBy: { expiresAt: 'desc' },
    });
    if (activeFlag) {
      sum += AGENT_RISK_FLAG_BUMP;
      reasonCodes.push(
        `agent_risk_flag:${activeFlag.reason}:${AGENT_RISK_FLAG_BUMP}`,
      );
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

    // Phase 10b: AI advisory risk scoring — strictly additive, see class
    // doc comment. Never re-derives anything steps above already decided;
    // `null` (no advisory available, for any reason) leaves
    // `finalRiskScore` untouched.
    const advisory = await this.aiAdvisoryClient.analyzeRisk({
      actionDescription: `Agent action: ${input.toolId}.${input.actionId} on resource "${input.resource}"`,
      context: `taskId=${input.task.id} riskCeiling=${input.task.riskCeiling} delegationDepth=${ancestors.length} deterministicRiskScore=${deterministicRiskScore}`,
      tenantId: input.tenantId,
      // Phase 15a (Section 53): lets AiAdvisoryClient's residency gate
      // independently block this specific call to an external provider
      // when the action is RESTRICTED, regardless of the tenant's
      // allowExternalAi flag — see that class's residencyAllows. undefined
      // (no registered ToolAction) is treated identically to any other
      // non-RESTRICTED classification there.
      classification: registered?.action.classification,
    });

    let aiAdvisoryScore: number | null = null;
    if (advisory) {
      aiAdvisoryScore = clamp(advisory.score, MIN_SCORE, MAX_SCORE);
      reasonCodes.push(`ai_advisory_score:${aiAdvisoryScore}`);
      reasonCodes.push(
        `ai_advisory_recommended_action:${advisory.recommendedAction}`,
      );
      for (const signal of advisory.signals) {
        reasonCodes.push(`ai_advisory_signal:${signal}`);
      }
    }

    const finalRiskScore = clamp(
      Math.max(deterministicRiskScore, aiAdvisoryScore ?? MIN_SCORE),
      MIN_SCORE,
      MAX_SCORE,
    );

    return {
      deterministicRiskScore,
      aiAdvisoryScore,
      finalRiskScore,
      reasonCodes,
    };
  }
}
