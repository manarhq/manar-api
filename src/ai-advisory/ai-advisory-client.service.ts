import { randomUUID } from 'node:crypto';
import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as grpc from '@grpc/grpc-js';
import {
  AnalysisServiceClient,
  dlpAnalysisResult_SeverityToJSON,
  dlpFinding_TypeToJSON,
  policyRuleDraft_EffectToJSON,
  riskAnalysisResult_RecommendedActionToJSON,
  type AuditInvestigationResult,
  type DlpAnalysisResult,
  type IncidentSummaryResult,
  type PolicyDraftResult,
  type PromptInjectionAnalysisResult,
  type RiskAnalysisResult,
} from '@manar-ai/grpc-client';
import type { AppConfig } from '../config/env.validation';
import { getCorrelationId } from '../logging/correlation-id.store';
import { ControlPrismaService } from '../database/control-prisma.service';
import type { DataClassification } from '../common/data-classification';
import { isExternalAiProvider } from './ai-advisory.config';

export interface RiskAdvisory {
  score: number;
  confidence: number;
  signals: string[];
  explanation: string;
  recommendedAction: string;
}

export interface PromptInjectionAdvisory {
  detected: boolean;
  confidence: number;
  indicators: string[];
  explanation: string;
}

export interface DlpFindingAdvisory {
  type: string;
  confidence: number;
  redactedPreview: string;
  source: string;
}

export interface DlpAdvisory {
  findings: DlpFindingAdvisory[];
  overallSeverity: string;
}

/** Phase 10c — `AiAdvisoryClient.summarizeIncident`'s advisory result. See `IncidentSummaryResult`'s proto doc comment for the "advisory-only, never presented as confirmed" posture every field here carries. */
export interface IncidentSummaryAdvisory {
  summary: string;
  keyEvents: string[];
  probableRootCause: string;
  recommendedNextSteps: string[];
  confidence: number;
  explanation: string;
}

/** Mirrors `PolicyRuleDraft` (the proto message), with `effect` already converted to the same string form `PolicyRuleSchema.effect` uses (`ALLOW`/`DENY`/`REQUIRE_APPROVAL`) — see `suggestPolicy`'s doc comment for why. */
export interface PolicyRuleDraftAdvisory {
  name: string;
  toolId: string;
  actionId: string;
  resourcePattern: string;
  effect: 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL';
  riskWeight: number;
  riskFloor: number;
  description: string;
}

/** Phase 10c — `AiAdvisoryClient.suggestPolicy`'s advisory result. Never auto-published — see that method's doc comment. */
export interface PolicyDraftAdvisory {
  rules: PolicyRuleDraftAdvisory[];
  explanation: string;
  confidence: number;
}

/** Phase 10c — `AiAdvisoryClient.investigateAudit`'s advisory result. */
export interface AuditInvestigationAdvisory {
  answer: string;
  citations: string[];
  confidence: number;
  explanation: string;
}

/**
 * The only place in this codebase that ever calls manar-ai's gRPC
 * `AnalysisService` (Phase 10b — see docs/ai-security-model.md; Phase 10c
 * adds `summarizeIncident`/`suggestPolicy`/`investigateAudit`, which follow
 * the identical timeout/circuit-breaker/data-residency/fail-safe contract
 * documented below, wrapping three additional RPCs rather than any new
 * resilience logic). Every public method has the identical contract: on
 * success, a real advisory
 * result; on **any** failure (timeout, transport error, non-OK gRPC
 * status, or the circuit being open) a `null`/absent result — this class
 * never throws out to a caller, and a caller must treat `null` as "no AI
 * signal available," never as an error to propagate (Section 80's
 * mandatory "AI outage does not create fail-open authorization"
 * invariant — the deterministic pipeline already stands on its own and
 * must behave identically whether this class returns real signals or
 * `null` throughout).
 *
 * Two resilience mechanisms, both configured via `AiAdvisoryConfigSchema`:
 *
 *   - **Per-RPC deadline** (`AI_ADVISORY_TIMEOUT_MS`, default 2000ms):
 *     `RiskEngine.score`/`CredentialBrokerService.invoke` are on hot,
 *     synchronous request paths — an unreachable or slow manar-ai must add
 *     bounded, small, predictable latency, never hang the pipeline. 2s is
 *     chosen as generous enough for a healthy same-network gRPC call under
 *     load, but short enough that even a fully-blocked authorize/invoke
 *     call stays well inside normal HTTP client timeouts.
 *   - **Circuit breaker** (`AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD`/
 *     `_COOLDOWN_MS`, defaults 3 consecutive failures / 30s cooldown): once
 *     manar-ai has failed `threshold` calls in a row, every subsequent call
 *     for `cooldownMs` returns `null` immediately, with no RPC attempted at
 *     all — avoids paying the full timeout on every single request while
 *     manar-ai is known to be down (a real outage is far more likely to
 *     last seconds-to-minutes than to resolve between two consecutive
 *     requests). After the cooldown elapses, the next call is let through
 *     as a trial: success closes the circuit (resets the failure count),
 *     failure re-opens it for another full cooldown.
 *
 * `confidence == 0.0` on `RiskAnalysisResult`/`PromptInjectionAnalysisResult`
 * is manar-ai's own documented fail-secure marker for "the AI layer didn't
 * actually run" (see manar-ai's docs/ai-security-model.md's "Fail loudly,
 * never fail open or fail silent" section) — this class treats that
 * identically to a transport-level failure (returns `null`), so a caller
 * never has to special-case "the RPC succeeded but carried no real signal"
 * versus "the RPC failed outright." `DlpAnalysisResult` has no equivalent
 * single confidence field (each finding carries its own, and the
 * deterministic layer's findings are always real regardless of AI
 * availability — see manar-ai's Section 73 doc) — `analyzeDlp` returns the
 * result as-is on any successful RPC, `null` only on a genuine RPC failure.
 */
@Injectable()
export class AiAdvisoryClient implements OnModuleDestroy {
  private readonly logger = new Logger(AiAdvisoryClient.name);
  private readonly client: AnalysisServiceClient;
  private readonly timeoutMs: number;
  private readonly circuitThreshold: number;
  private readonly circuitCooldownMs: number;
  private readonly provider: 'anthropic' | 'ollama' | 'vllm';

  private consecutiveFailures = 0;
  private circuitOpenUntil: number | null = null;

  constructor(
    configService: ConfigService<AppConfig, true>,
    private readonly control: ControlPrismaService,
  ) {
    const target = configService.get('AI_ADVISORY_GRPC_TARGET', {
      infer: true,
    });
    this.timeoutMs = configService.get('AI_ADVISORY_TIMEOUT_MS', {
      infer: true,
    });
    this.circuitThreshold = configService.get(
      'AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD',
      { infer: true },
    );
    this.circuitCooldownMs = configService.get(
      'AI_ADVISORY_CIRCUIT_BREAKER_COOLDOWN_MS',
      { infer: true },
    );
    this.provider = configService.get('AI_ADVISORY_PROVIDER', {
      infer: true,
    });
    // Plaintext, matching manar-ai's own deliberate Phase 10a scope call
    // (see docs/ai-security-model.md's "mTLS status" section) — both sides
    // of this contract agree mTLS is required before any real cross-network
    // deployment, not before this phase's local-infra integration.
    this.client = new AnalysisServiceClient(
      target,
      grpc.credentials.createInsecure(),
    );
  }

  onModuleDestroy(): void {
    this.client.close();
  }

  async analyzeRisk(input: {
    actionDescription: string;
    context: string;
    correlationId?: string;
    /** Phase 12a (Section 54): the requesting tenant — required so the data-residency gate below can consult its `allowExternalAi` flag before this call is allowed to reach an external provider. */
    tenantId: string;
    /** Phase 15a (Section 53): the specific tool action's resolved `ToolAction.classification`, when known — see `residencyAllows`'s doc comment for the independent `RESTRICTED` gate this enables. `undefined` (unregistered action, or a caller that hasn't threaded this through yet) is never treated as `RESTRICTED`. */
    classification?: DataClassification;
  }): Promise<RiskAdvisory | null> {
    if (
      !(await this.residencyAllows(
        input.tenantId,
        'AnalyzeRisk',
        input.classification,
      ))
    ) {
      return null;
    }
    const result = await this.call('AnalyzeRisk', () =>
      this.promisify<RiskAnalysisResult>((deadline, callback) =>
        this.client.analyzeRisk(
          {
            actionDescription: input.actionDescription,
            context: input.context,
            correlationId: input.correlationId ?? this.resolveCorrelationId(),
          },
          new grpc.Metadata(),
          { deadline },
          callback,
        ),
      ),
    );
    if (!result) return null;
    // manar-ai's documented fail-secure marker for "AI layer didn't run" —
    // see class doc comment.
    if (result.confidence <= 0) return null;
    return {
      score: result.score,
      confidence: result.confidence,
      signals: result.signals,
      explanation: result.explanation,
      recommendedAction: riskAnalysisResult_RecommendedActionToJSON(
        result.recommendedAction,
      ),
    };
  }

  async analyzePromptInjection(input: {
    content: string;
    source: string;
    correlationId?: string;
    /** Phase 12a (Section 54) — see `analyzeRisk`'s identical parameter doc comment. */
    tenantId: string;
    /** Phase 15a (Section 53) — see `analyzeRisk`'s identical parameter doc comment. */
    classification?: DataClassification;
  }): Promise<PromptInjectionAdvisory | null> {
    if (
      !(await this.residencyAllows(
        input.tenantId,
        'AnalyzePromptInjection',
        input.classification,
      ))
    ) {
      return null;
    }
    const result = await this.call('AnalyzePromptInjection', () =>
      this.promisify<PromptInjectionAnalysisResult>((deadline, callback) =>
        this.client.analyzePromptInjection(
          {
            content: input.content,
            source: input.source,
            correlationId: input.correlationId ?? this.resolveCorrelationId(),
          },
          new grpc.Metadata(),
          { deadline },
          callback,
        ),
      ),
    );
    if (!result) return null;
    if (result.confidence <= 0) return null;
    return {
      detected: result.detected,
      confidence: result.confidence,
      indicators: result.indicators,
      explanation: result.explanation,
    };
  }

  async analyzeDlp(input: {
    content: string;
    correlationId?: string;
    /** Phase 12a (Section 54) — see `analyzeRisk`'s identical parameter doc comment. */
    tenantId: string;
    /** Phase 15a (Section 53) — see `analyzeRisk`'s identical parameter doc comment. */
    classification?: DataClassification;
  }): Promise<DlpAdvisory | null> {
    if (
      !(await this.residencyAllows(
        input.tenantId,
        'AnalyzeDlp',
        input.classification,
      ))
    ) {
      return null;
    }
    const result = await this.call('AnalyzeDlp', () =>
      this.promisify<DlpAnalysisResult>((deadline, callback) =>
        this.client.analyzeDlp(
          {
            content: input.content,
            correlationId: input.correlationId ?? this.resolveCorrelationId(),
          },
          new grpc.Metadata(),
          { deadline },
          callback,
        ),
      ),
    );
    if (!result) return null;
    return {
      findings: result.findings.map((f) => ({
        type: dlpFinding_TypeToJSON(f.type),
        confidence: f.confidence,
        redactedPreview: f.redactedPreview,
        source: f.source,
      })),
      overallSeverity: dlpAnalysisResult_SeverityToJSON(result.overallSeverity),
    };
  }

  /**
   * Phase 10c — advisory summary of caller-supplied incident context (a
   * free-text description and/or human-readable summaries of related audit
   * events). `manar-api`'s `IncidentsController` is responsible for
   * resolving `relatedEvents` from the caller's own tenant before calling
   * this (this class never fetches anything itself — see
   * `docs/ai-security-model.md`). `confidence <= 0` (manar-ai's documented
   * fail-secure marker, same convention as `analyzeRisk`/
   * `analyzePromptInjection` above) returns `null` — never a fabricated-
   * looking summary presented as real.
   */
  async summarizeIncident(input: {
    description: string;
    relatedEvents: string[];
    correlationId?: string;
    /** Phase 12a (Section 54) — see `analyzeRisk`'s identical parameter doc comment. */
    tenantId: string;
    /** Phase 15a (Section 53) — see `analyzeRisk`'s identical parameter doc comment. */
    classification?: DataClassification;
  }): Promise<IncidentSummaryAdvisory | null> {
    if (
      !(await this.residencyAllows(
        input.tenantId,
        'SummarizeIncident',
        input.classification,
      ))
    ) {
      return null;
    }
    const result = await this.call('SummarizeIncident', () =>
      this.promisify<IncidentSummaryResult>((deadline, callback) =>
        this.client.summarizeIncident(
          {
            description: input.description,
            relatedEvents: input.relatedEvents,
            correlationId: input.correlationId ?? this.resolveCorrelationId(),
          },
          new grpc.Metadata(),
          { deadline },
          callback,
        ),
      ),
    );
    if (!result) return null;
    if (result.confidence <= 0) return null;
    return {
      summary: result.summary,
      keyEvents: result.keyEvents,
      probableRootCause: result.probableRootCause,
      recommendedNextSteps: result.recommendedNextSteps,
      confidence: result.confidence,
      explanation: result.explanation,
    };
  }

  /**
   * Phase 10c — converts a natural-language policy description into a
   * **draft** rule set matching Phase 6's `PolicyContentSchema` field-for-
   * field (`PolicyRuleDraft.effect`'s `EFFECT_*` enum is mapped to the same
   * bare `ALLOW`/`DENY`/`REQUIRE_APPROVAL` strings `PolicyRuleSchema.effect`
   * uses, so the caller can hand `rules` straight to that schema without any
   * further translation). **Never published by this class or anything it
   * calls** — `PolicyController.suggestPolicy` (the only caller) must
   * persist the result as a `DRAFT` `PolicyVersion` and require the normal
   * human `/policies/:id/versions/:versionId/publish` step, exactly like
   * any other draft. `confidence <= 0` returns `null` (manar-ai's documented
   * fail-secure marker — `rules` is guaranteed empty in that case per the
   * proto's own doc comment, but this class returns `null` regardless,
   * consistent with every other advisory method here).
   */
  async suggestPolicy(input: {
    naturalLanguageDescription: string;
    correlationId?: string;
    /** Phase 12a (Section 54) — see `analyzeRisk`'s identical parameter doc comment. */
    tenantId: string;
    /** Phase 15a (Section 53) — see `analyzeRisk`'s identical parameter doc comment. */
    classification?: DataClassification;
  }): Promise<PolicyDraftAdvisory | null> {
    if (
      !(await this.residencyAllows(
        input.tenantId,
        'SuggestPolicy',
        input.classification,
      ))
    ) {
      return null;
    }
    const result = await this.call('SuggestPolicy', () =>
      this.promisify<PolicyDraftResult>((deadline, callback) =>
        this.client.suggestPolicy(
          {
            naturalLanguageDescription: input.naturalLanguageDescription,
            correlationId: input.correlationId ?? this.resolveCorrelationId(),
          },
          new grpc.Metadata(),
          { deadline },
          callback,
        ),
      ),
    );
    if (!result) return null;
    if (result.confidence <= 0) return null;
    return {
      rules: result.rules.map((rule) => ({
        name: rule.name,
        toolId: rule.toolId,
        actionId: rule.actionId,
        resourcePattern: rule.resourcePattern,
        effect: policyRuleDraft_EffectToJSON(rule.effect).replace(
          /^EFFECT_/,
          '',
        ) as 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL',
        riskWeight: rule.riskWeight,
        riskFloor: rule.riskFloor,
        description: rule.description,
      })),
      explanation: result.explanation,
      confidence: result.confidence,
    };
  }

  /**
   * Phase 10c — answers a question (e.g. "why was this action denied?")
   * using only the caller-supplied `retrievedContext`. **This class performs
   * no retrieval of its own** — `AuditController.investigateAudit` (the only
   * caller) must have already produced `retrievedContext` via its own
   * tenant-scoped `AuditSearchService` query before calling this, so that
   * manar-ai only ever sees already-authorized data for this specific
   * caller (see `docs/ai-security-model.md`'s RAG/retrieval boundary
   * section). `confidence <= 0` returns `null` — never a fabricated answer
   * presented as authoritative.
   */
  async investigateAudit(input: {
    question: string;
    retrievedContext: string[];
    correlationId?: string;
    /** Phase 12a (Section 54) — see `analyzeRisk`'s identical parameter doc comment. */
    tenantId: string;
    /** Phase 15a (Section 53) — see `analyzeRisk`'s identical parameter doc comment. */
    classification?: DataClassification;
  }): Promise<AuditInvestigationAdvisory | null> {
    if (
      !(await this.residencyAllows(
        input.tenantId,
        'InvestigateAudit',
        input.classification,
      ))
    ) {
      return null;
    }
    const result = await this.call('InvestigateAudit', () =>
      this.promisify<AuditInvestigationResult>((deadline, callback) =>
        this.client.investigateAudit(
          {
            question: input.question,
            retrievedContext: input.retrievedContext,
            correlationId: input.correlationId ?? this.resolveCorrelationId(),
          },
          new grpc.Metadata(),
          { deadline },
          callback,
        ),
      ),
    );
    if (!result) return null;
    if (result.confidence <= 0) return null;
    return {
      answer: result.answer,
      citations: result.citations,
      confidence: result.confidence,
      explanation: result.explanation,
    };
  }

  private resolveCorrelationId(): string {
    return getCorrelationId() ?? randomUUID();
  }

  /**
   * Phase 12a (Section 54, data residency enforcement) — the fix for a
   * real, previously-unenforced gap: Phase 2 gave every `Tenant` an
   * `allowExternalAi` flag (default `false`, the safe default) but nothing
   * ever checked it before this phase. Runs *before* the circuit-breaker
   * gate in `call()` (and before any RPC is even attempted) so a
   * residency block never counts as a "failure" toward the circuit
   * breaker's consecutive-failure count — this is a policy decision, not
   * an outage.
   *
   * `AI_ADVISORY_PROVIDER` (this side's own declaration of which provider
   * `manar-ai` is currently configured to use — see that config field's
   * doc comment for why `manar-api` can't ask `manar-ai` this over gRPC)
   * short-circuits to "allowed" for any self-hosted provider
   * (`ollama`/`vllm`) without even reading the tenant row — residency
   * only matters once a call could actually leave this deployment's own
   * infrastructure.
   *
   * Fails **closed**: a tenant lookup failure (unexpected control-DB
   * error, unknown tenant id) is treated as "not allowed," never as
   * "allowed by default" — this is a data-residency *restriction*, and an
   * inability to confirm a tenant opted in must never silently fall back
   * to permissive behavior.
   *
   * On a block, this returns `false` and every caller (`analyzeRisk`/
   * `analyzePromptInjection`/`analyzeDlp`) returns `null` immediately —
   * the *exact same* "no AI signal available" outcome Phase 10b already
   * established for a `manar-ai` outage (see class doc comment's
   * "Never throws" section). This is a deliberate reuse, not a new
   * response shape: every existing caller (`RiskEngine.score`,
   * `CredentialBrokerService`'s DLP/prompt-injection checkpoints) already
   * treats `null` as "proceed using only the deterministic pipeline,"
   * which is exactly the correct behavior here too.
   *
   * **Phase 15a (Section 53) — the classification gate is a second,
   * independent check, layered on top of (not instead of) the
   * `allowExternalAi` gate above.** Section 53's own worked example is
   * literally "RESTRICTED data cannot be sent to an external cloud AI
   * provider" — a `RESTRICTED`-classified tool action's content is never
   * sent to an external provider, *regardless* of whether this tenant has
   * `allowExternalAi = true`. Checked first (before ever touching the
   * control DB), for two reasons: it needs no tenant lookup at all (a
   * classification-level restriction doesn't depend on tenant
   * configuration), and it must never be bypassable by a permissive
   * tenant flag — a tenant that generally allows external AI still may
   * never leak a RESTRICTED action's data that way. `undefined`/any
   * non-`RESTRICTED` classification is unaffected by this check and falls
   * through to the existing `allowExternalAi` gate unchanged.
   */
  private async residencyAllows(
    tenantId: string,
    rpcName: string,
    classification?: DataClassification,
  ): Promise<boolean> {
    if (!isExternalAiProvider(this.provider)) return true;

    if (classification === 'RESTRICTED') {
      this.logger.log(
        `Skipping manar-ai ${rpcName} for tenant "${tenantId}": the tool action's classification is RESTRICTED — no RPC attempted to external provider "${this.provider}" regardless of this tenant's allowExternalAi flag (Section 53 data classification enforcement).`,
      );
      return false;
    }

    try {
      const tenant = await this.control.tenant.findUnique({
        where: { id: tenantId },
        select: { allowExternalAi: true },
      });
      if (tenant?.allowExternalAi === true) return true;

      this.logger.log(
        `Skipping manar-ai ${rpcName} for tenant "${tenantId}": provider "${this.provider}" is external and this tenant's allowExternalAi is not true — no RPC attempted (Section 54 data residency enforcement).`,
      );
      return false;
    } catch (error) {
      this.logger.warn(
        `Could not resolve tenant "${tenantId}"'s allowExternalAi flag before an external-provider AI call — failing closed (treating as disallowed): ${error instanceof Error ? error.message : String(error)}`,
      );
      return false;
    }
  }

  /**
   * The single choke point every RPC goes through: circuit-breaker
   * gate, timeout/error handling, and failure-count bookkeeping — see
   * class doc comment for the full state machine. Never throws; `null`
   * is the uniform "no signal" outcome for every caller.
   */
  private async call<T>(
    rpcName: string,
    fn: () => Promise<T>,
  ): Promise<T | null> {
    if (this.circuitOpenUntil !== null) {
      if (Date.now() < this.circuitOpenUntil) {
        // Circuit open — skip the call entirely rather than paying the
        // full timeout on a backend already known to be failing.
        return null;
      }
      // Cooldown elapsed: let this one call through as a half-open trial.
      // `onFailure`/`onSuccess` below decide whether the circuit re-opens
      // or fully closes.
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure(rpcName, error);
      return null;
    }
  }

  private onSuccess(): void {
    if (this.consecutiveFailures > 0 || this.circuitOpenUntil !== null) {
      this.logger.log(
        `manar-ai AnalysisService call succeeded — circuit breaker reset`,
      );
    }
    this.consecutiveFailures = 0;
    this.circuitOpenUntil = null;
  }

  private onFailure(rpcName: string, error: unknown): void {
    this.consecutiveFailures += 1;
    this.logger.warn(
      `manar-ai AnalysisService.${rpcName} failed (consecutive failures: ${this.consecutiveFailures}): ${error instanceof Error ? error.message : String(error)}`,
    );
    if (this.consecutiveFailures >= this.circuitThreshold) {
      const wasOpen = this.circuitOpenUntil !== null;
      this.circuitOpenUntil = Date.now() + this.circuitCooldownMs;
      if (!wasOpen) {
        this.logger.warn(
          `manar-ai AnalysisService circuit breaker OPEN for ${this.circuitCooldownMs}ms after ${this.consecutiveFailures} consecutive failures`,
        );
      }
    }
  }

  /** Wraps a grpc-js callback-style unary call in a Promise, applying this client's configured deadline. */
  private promisify<T>(
    invoke: (
      deadline: grpc.Deadline,
      callback: (error: grpc.ServiceError | null, response: T) => void,
    ) => grpc.ClientUnaryCall,
  ): Promise<T> {
    const deadline = Date.now() + this.timeoutMs;
    return new Promise<T>((resolve, reject) => {
      invoke(deadline, (error, response) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(response);
      });
    });
  }
}
