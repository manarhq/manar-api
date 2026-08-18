import { randomUUID } from 'node:crypto';
import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as grpc from '@grpc/grpc-js';
import {
  AnalysisServiceClient,
  dlpAnalysisResult_SeverityToJSON,
  dlpFinding_TypeToJSON,
  riskAnalysisResult_RecommendedActionToJSON,
  type DlpAnalysisResult,
  type PromptInjectionAnalysisResult,
  type RiskAnalysisResult,
} from '@manar-ai/grpc-client';
import type { AppConfig } from '../config/env.validation';
import { getCorrelationId } from '../logging/correlation-id.store';

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

/**
 * The only place in this codebase that ever calls manar-ai's gRPC
 * `AnalysisService` (Phase 10b — see docs/ai-security-model.md). Every
 * public method has the identical contract: on success, a real advisory
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

  private consecutiveFailures = 0;
  private circuitOpenUntil: number | null = null;

  constructor(configService: ConfigService<AppConfig, true>) {
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
  }): Promise<RiskAdvisory | null> {
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
  }): Promise<PromptInjectionAdvisory | null> {
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
  }): Promise<DlpAdvisory | null> {
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

  private resolveCorrelationId(): string {
    return getCorrelationId() ?? randomUUID();
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
