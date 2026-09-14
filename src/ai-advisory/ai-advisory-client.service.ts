import { readFileSync } from 'node:fs';
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
import {
  aiAdvisoryTlsEnabled,
  assertAiAdvisoryTlsMaterial,
  isExternalAiProvider,
} from './ai-advisory.config';

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

/** Mirrors `PolicyRuleDraft` (the proto message), with `effect` already converted to the same string form `PolicyRuleSchema.effect` uses (`ALLOW`/`DENY`/`APPROVAL_REQUIRED`) — see `suggestPolicy`'s doc comment for why. */
export interface PolicyRuleDraftAdvisory {
  name: string;
  toolId: string;
  actionId: string;
  resourcePattern: string;
  effect: 'ALLOW' | 'DENY' | 'APPROVAL_REQUIRED';
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
 * The two independent latency/failure lanes `AiAdvisoryClient` maintains —
 * see the class doc comment's "Two resilience mechanisms" section for why
 * these must never share timeout or circuit-breaker state.
 *
 *   - `hot`: `AnalyzeRisk`/`AnalyzePromptInjection`/`AnalyzeDlp` — inline on
 *     the authorization/tool-invocation path.
 *   - `longform`: `SummarizeIncident`/`SuggestPolicy`/`InvestigateAudit` —
 *     explicit, user-initiated LLM generation, off the authorization path.
 */
export type AiRpcLane = 'hot' | 'longform';

/** Per-lane circuit-breaker state — see `call<T>()`'s doc comment. */
interface CircuitBreakerState {
  consecutiveFailures: number;
  circuitOpenUntil: number | null;
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
 * Two resilience mechanisms, both configured via `AiAdvisoryConfigSchema`,
 * and both split into two independent **lanes** (`AiRpcLane`: `'hot'` |
 * `'longform'`) — this split is deliberate, and the reasoning below is why
 * a future change must not collapse it back into shared state:
 *
 *   - **hot** — `AnalyzeRisk`/`AnalyzePromptInjection`/`AnalyzeDlp`.
 *     `RiskEngine.score`/`CredentialBrokerService.invoke` call these
 *     inline, synchronously, on the authorization/tool-invocation path.
 *     Latency here is a security property: an unreachable or slow manar-ai
 *     must add bounded, small, predictable latency, never hang the
 *     pipeline.
 *   - **longform** — `SummarizeIncident`/`SuggestPolicy`/`InvestigateAudit`
 *     (Phase 10c). These are explicit, user-initiated LLM-generation calls,
 *     off the authorization path — nothing blocks on them, and no model
 *     completes an incident summary in the hot lane's ~2s budget.
 *
 *   The two lanes fail for structurally different reasons: the hot lane
 *   fails when manar-ai itself is unreachable or overloaded; the long-form
 *   lane fails when a model is merely slow to generate. A user clicking
 *   "Summarize" a few times and tripping the long-form breaker must never
 *   take risk scoring, prompt-injection detection, or DLP dark as
 *   collateral damage — that coupling previously disabled the entire AI
 *   layer platform-wide off of nothing but slow generation, which is
 *   exactly what a shared breaker would reintroduce. Each lane therefore
 *   gets its own deadline, its own consecutive-failure count, and its own
 *   circuit-open-until timestamp; `promisify`/`call`/`onSuccess`/
 *   `onFailure` all take a lane and only ever read/write that lane's own
 *   state.
 *
 *   - **Per-RPC deadline**: `AI_ADVISORY_TIMEOUT_MS` (default 2000ms) for
 *     the hot lane, `AI_ADVISORY_LONGFORM_TIMEOUT_MS` (default 30000ms) for
 *     the long-form lane. 2s is chosen as generous enough for a healthy
 *     same-network gRPC call under load, but short enough that even a
 *     fully-blocked authorize/invoke call stays well inside normal HTTP
 *     client timeouts; 30s is generous enough for a real LLM generation.
 *   - **Circuit breaker**: `AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD`/
 *     `_COOLDOWN_MS` (defaults 3 consecutive failures / 30s cooldown) for
 *     the hot lane, `AI_ADVISORY_LONGFORM_CIRCUIT_BREAKER_THRESHOLD`/
 *     `_COOLDOWN_MS` (same defaults) for the long-form lane. Once a lane
 *     has failed `threshold` calls in a row, every subsequent call on
 *     *that lane* for `cooldownMs` returns `null` immediately, with no RPC
 *     attempted at all — avoids paying the full timeout on every single
 *     request while manar-ai is known to be down on that lane (a real
 *     outage is far more likely to last seconds-to-minutes than to resolve
 *     between two consecutive requests). After the cooldown elapses, the
 *     next call on that lane is let through as a trial: success closes the
 *     circuit (resets the failure count), failure re-opens it for another
 *     full cooldown.
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
  private readonly provider: 'anthropic' | 'ollama' | 'vllm';

  /** Per-lane timeout/circuit-breaker config — see `AiRpcLane`'s doc comment. */
  private readonly timeoutMsByLane: Record<AiRpcLane, number>;
  private readonly circuitThresholdByLane: Record<AiRpcLane, number>;
  private readonly circuitCooldownMsByLane: Record<AiRpcLane, number>;

  /** Per-lane circuit-breaker state, mutated only by `onSuccess`/`onFailure` for that same lane — see `call<T>()`'s doc comment. */
  private readonly circuitStateByLane: Record<AiRpcLane, CircuitBreakerState> =
    {
      hot: { consecutiveFailures: 0, circuitOpenUntil: null },
      longform: { consecutiveFailures: 0, circuitOpenUntil: null },
    };

  constructor(
    configService: ConfigService<AppConfig, true>,
    private readonly control: ControlPrismaService,
  ) {
    const target = configService.get('AI_ADVISORY_GRPC_TARGET', {
      infer: true,
    });
    this.timeoutMsByLane = {
      hot: configService.get('AI_ADVISORY_TIMEOUT_MS', { infer: true }),
      longform: configService.get('AI_ADVISORY_LONGFORM_TIMEOUT_MS', {
        infer: true,
      }),
    };
    this.circuitThresholdByLane = {
      hot: configService.get('AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD', {
        infer: true,
      }),
      longform: configService.get(
        'AI_ADVISORY_LONGFORM_CIRCUIT_BREAKER_THRESHOLD',
        { infer: true },
      ),
    };
    this.circuitCooldownMsByLane = {
      hot: configService.get('AI_ADVISORY_CIRCUIT_BREAKER_COOLDOWN_MS', {
        infer: true,
      }),
      longform: configService.get(
        'AI_ADVISORY_LONGFORM_CIRCUIT_BREAKER_COOLDOWN_MS',
        { infer: true },
      ),
    };
    this.provider = configService.get('AI_ADVISORY_PROVIDER', {
      infer: true,
    });
    // Release 2026-11-11: manar-ai's `AnalysisService` now binds
    // `add_secure_port` with `require_client_auth=True` plus a peer-identity
    // interceptor, and refuses to bind plaintext at all when its own
    // ENVIRONMENT is staging/production. It still binds plaintext for
    // local/development/test, so the default here stays insecure and the
    // developer stack is unchanged — see AI_ADVISORY_TLS_ENABLED's doc
    // comment for the certificate identity manar-ai will require
    // (`manar-api` or `manar-api-worker` as CN/SAN, issued by the same
    // internal CA; manar-ai does not consult the system trust store).
    //
    // The material is validated before the channel is built, so a
    // half-configured deployment fails at startup with the missing variable
    // named, rather than at connect time as a generic "AI advisory
    // unavailable" — which is the correct fail-secure behaviour but a
    // useless diagnostic.
    assertAiAdvisoryTlsMaterial({
      AI_ADVISORY_TLS_ENABLED: configService.get('AI_ADVISORY_TLS_ENABLED', {
        infer: true,
      }),
      AI_ADVISORY_TLS_CA_FILE: configService.get('AI_ADVISORY_TLS_CA_FILE', {
        infer: true,
      }),
      AI_ADVISORY_TLS_CERT_FILE: configService.get(
        'AI_ADVISORY_TLS_CERT_FILE',
        { infer: true },
      ),
      AI_ADVISORY_TLS_KEY_FILE: configService.get('AI_ADVISORY_TLS_KEY_FILE', {
        infer: true,
      }),
    });

    const tlsEnabled = aiAdvisoryTlsEnabled({
      AI_ADVISORY_TLS_ENABLED: configService.get('AI_ADVISORY_TLS_ENABLED', {
        infer: true,
      }),
    });

    if (tlsEnabled) {
      // Read synchronously in the constructor on purpose: an unreadable or
      // missing certificate must stop the process from starting, not
      // surface later as an intermittently failing dependency.
      const credentials = grpc.credentials.createSsl(
        readFileSync(
          configService.get('AI_ADVISORY_TLS_CA_FILE', {
            infer: true,
          }),
        ),
        readFileSync(
          configService.get('AI_ADVISORY_TLS_KEY_FILE', {
            infer: true,
          }),
        ),
        readFileSync(
          configService.get('AI_ADVISORY_TLS_CERT_FILE', {
            infer: true,
          }),
        ),
      );
      this.logger.log(
        `manar-ai AnalysisService channel secured with mTLS to ${target}`,
      );
      this.client = new AnalysisServiceClient(target, credentials);
    } else {
      this.logger.warn(
        `manar-ai AnalysisService channel is PLAINTEXT to ${target}. This is supported only against a local/development/test manar-ai; set AI_ADVISORY_TLS_ENABLED=true with the CA/certificate/key for any real deployment.`,
      );
      this.client = new AnalysisServiceClient(
        target,
        grpc.credentials.createInsecure(),
      );
    }
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
    const result = await this.call('hot', 'AnalyzeRisk', () =>
      this.promisify<RiskAnalysisResult>('hot', (deadline, callback) =>
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
    const result = await this.call('hot', 'AnalyzePromptInjection', () =>
      this.promisify<PromptInjectionAnalysisResult>(
        'hot',
        (deadline, callback) =>
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
    const result = await this.call('hot', 'AnalyzeDlp', () =>
      this.promisify<DlpAnalysisResult>('hot', (deadline, callback) =>
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
    const result = await this.call('longform', 'SummarizeIncident', () =>
      this.promisify<IncidentSummaryResult>('longform', (deadline, callback) =>
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
   * bare `ALLOW`/`DENY`/`APPROVAL_REQUIRED` strings `PolicyRuleSchema.effect`
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
    const result = await this.call('longform', 'SuggestPolicy', () =>
      this.promisify<PolicyDraftResult>('longform', (deadline, callback) =>
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
        ) as 'ALLOW' | 'DENY' | 'APPROVAL_REQUIRED',
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
    const result = await this.call('longform', 'InvestigateAudit', () =>
      this.promisify<AuditInvestigationResult>(
        'longform',
        (deadline, callback) =>
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
   * class doc comment for the full state machine. Reads and writes only
   * `lane`'s own `CircuitBreakerState` (`this.circuitStateByLane[lane]`) —
   * a hot-lane call must never observe or affect the long-form breaker's
   * state, and vice versa. Never throws; `null` is the uniform "no signal"
   * outcome for every caller.
   */
  private async call<T>(
    lane: AiRpcLane,
    rpcName: string,
    fn: () => Promise<T>,
  ): Promise<T | null> {
    const state = this.circuitStateByLane[lane];
    if (state.circuitOpenUntil !== null) {
      if (Date.now() < state.circuitOpenUntil) {
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
      this.onSuccess(lane);
      return result;
    } catch (error) {
      this.onFailure(lane, rpcName, error);
      return null;
    }
  }

  private onSuccess(lane: AiRpcLane): void {
    const state = this.circuitStateByLane[lane];
    if (state.consecutiveFailures > 0 || state.circuitOpenUntil !== null) {
      this.logger.log(
        `manar-ai AnalysisService call succeeded on the "${lane}" lane — circuit breaker reset`,
      );
    }
    state.consecutiveFailures = 0;
    state.circuitOpenUntil = null;
  }

  private onFailure(lane: AiRpcLane, rpcName: string, error: unknown): void {
    const state = this.circuitStateByLane[lane];
    state.consecutiveFailures += 1;
    this.logger.warn(
      `manar-ai AnalysisService.${rpcName} failed on the "${lane}" lane (consecutive failures: ${state.consecutiveFailures}): ${error instanceof Error ? error.message : String(error)}`,
    );
    const threshold = this.circuitThresholdByLane[lane];
    if (state.consecutiveFailures >= threshold) {
      const wasOpen = state.circuitOpenUntil !== null;
      const cooldownMs = this.circuitCooldownMsByLane[lane];
      state.circuitOpenUntil = Date.now() + cooldownMs;
      if (!wasOpen) {
        this.logger.warn(
          `manar-ai AnalysisService circuit breaker OPEN on the "${lane}" lane for ${cooldownMs}ms after ${state.consecutiveFailures} consecutive failures`,
        );
      }
    }
  }

  /** Wraps a grpc-js callback-style unary call in a Promise, applying `lane`'s configured deadline (`this.timeoutMsFor(lane)`). */
  private promisify<T>(
    lane: AiRpcLane,
    invoke: (
      deadline: grpc.Deadline,
      callback: (error: grpc.ServiceError | null, response: T) => void,
    ) => grpc.ClientUnaryCall,
  ): Promise<T> {
    const deadline = Date.now() + this.timeoutMsFor(lane);
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

  private timeoutMsFor(lane: AiRpcLane): number {
    return this.timeoutMsByLane[lane];
  }
}
