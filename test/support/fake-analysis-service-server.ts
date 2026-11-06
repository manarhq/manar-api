import * as grpc from '@grpc/grpc-js';
import {
  AnalysisServiceService,
  type AnalysisEvent,
  type AnalysisServiceServer,
  type AuditInvestigationResult,
  type DlpAnalysisResult,
  type IncidentSummaryResult,
  type PolicyDraftResult,
  type PromptInjectionAnalysisResult,
  type RiskAnalysisResult,
} from '@manar-ai/grpc-client';

/**
 * A real gRPC server implementing manar-ai's exact `AnalysisService`
 * contract (the same generated `@manar-ai/grpc-client` types
 * `AiAdvisoryClient` itself uses) — not a mock of `AiAdvisoryClient`.
 * Stands in for the real `manar-ai` container in tests that need
 * *content-controlled* AI signals (a genuine high-confidence risk score, a
 * genuine prompt-injection detection) — see
 * `test/ai-advisory.e2e-spec.ts`'s own doc comment for why: the real
 * `manar-ai` container in this repo's `deploy/docker-compose.yml` is
 * deliberately configured with an unresolvable AI backend (fast, real
 * fail-secure responses — good for outage/DLP-deterministic-layer
 * scenarios, useless for asserting on a *specific* AI-reported score or
 * detection, since a real LLM's few-second latency is incompatible with
 * `AiAdvisoryClient`'s sub-2-second budget on the hot authorization path).
 * This class exercises the identical wire protocol, generated
 * (de)serialization, and `AnalysisServiceClient` code `AiAdvisoryClient`
 * uses against the real container — only the canned response content, and
 * optionally an artificial response delay (for exercising the timeout
 * path), are test-controlled.
 */
export class FakeAnalysisServiceServer {
  private server: grpc.Server | undefined;

  readonly callCounts = {
    analyzeRisk: 0,
    analyzePromptInjection: 0,
    analyzeDlp: 0,
    summarizeIncident: 0,
    suggestPolicy: 0,
    investigateAudit: 0,
    streamSummarizeIncident: 0,
    streamSuggestPolicy: 0,
    streamInvestigateAudit: 0,
  };

  /** Text pieces the streaming RPCs send before the result; `streamGapMs` apart. */
  streamDeltas: string[] = [];
  /** Character counts the policy stream sends as progress before the result. */
  streamProgress: number[] = [];
  streamGapMs = 0;
  /** When set, the streaming RPCs fail with this status after the deltas instead of sending the result. */
  streamFailsWith: grpc.status | undefined;

  /** Artificial delay (ms) before responding to any RPC — set high to exercise `AiAdvisoryClient`'s timeout path. */
  responseDelayMs = 0;

  riskResult: RiskAnalysisResult = {
    score: 0,
    confidence: 0,
    signals: [],
    explanation: '',
    recommendedAction: 0,
  };
  promptInjectionResult: PromptInjectionAnalysisResult = {
    detected: false,
    confidence: 0,
    indicators: [],
    explanation: '',
  };
  /** When set, only content containing this marker gets `promptInjectionResult`; anything else is reported clean. */
  promptInjectionMarker: string | undefined;
  dlpResult: DlpAnalysisResult = { findings: [], overallSeverity: 0 };
  incidentSummaryResult: IncidentSummaryResult = {
    summary: '',
    keyEvents: [],
    probableRootCause: '',
    recommendedNextSteps: [],
    confidence: 0,
    explanation: '',
  };
  policyDraftResult: PolicyDraftResult = {
    rules: [],
    explanation: '',
    confidence: 0,
  };
  auditInvestigationResult: AuditInvestigationResult = {
    answer: '',
    citations: [],
    confidence: 0,
    explanation: '',
  };

  /**
   * The exact request payload the fake server most recently received for
   * `InvestigateAudit` — lets a test assert precisely what `AiAdvisoryClient`
   * sent over the wire (e.g. `retrievedContext`), the same "assert at the
   * network level, never just 'it returned something'" posture this repo's
   * data-residency tests already establish.
   */
  lastInvestigateAuditRequest:
    { question: string; retrievedContext: string[] } | undefined;

  async start(): Promise<string> {
    this.server = new grpc.Server();
    const impl: AnalysisServiceServer = {
      analyzeRisk: (_call, callback) => {
        this.callCounts.analyzeRisk += 1;
        this.respond(callback, () => this.riskResult);
      },
      analyzePromptInjection: (call, callback) => {
        this.callCounts.analyzePromptInjection += 1;
        this.respond(callback, () =>
          this.promptInjectionMarker === undefined ||
          call.request.content.includes(this.promptInjectionMarker)
            ? this.promptInjectionResult
            : {
                detected: false,
                confidence: 0,
                indicators: [],
                explanation: '',
              },
        );
      },
      analyzeDlp: (_call, callback) => {
        this.callCounts.analyzeDlp += 1;
        this.respond(callback, () => this.dlpResult);
      },
      summarizeIncident: (_call, callback) => {
        this.callCounts.summarizeIncident += 1;
        this.respond(callback, () => this.incidentSummaryResult);
      },
      suggestPolicy: (_call, callback) => {
        this.callCounts.suggestPolicy += 1;
        this.respond(callback, () => this.policyDraftResult);
      },
      investigateAudit: (call, callback) => {
        this.callCounts.investigateAudit += 1;
        this.lastInvestigateAuditRequest = {
          question: call.request.question,
          retrievedContext: call.request.retrievedContext,
        };
        this.respond(callback, () => this.auditInvestigationResult);
      },
      streamSummarizeIncident: (call) => {
        this.callCounts.streamSummarizeIncident += 1;
        void this.stream(call, () => ({
          incidentSummary: this.incidentSummaryResult,
        }));
      },
      streamSuggestPolicy: (call) => {
        this.callCounts.streamSuggestPolicy += 1;
        void this.stream(
          call,
          () => ({ policyDraft: this.policyDraftResult }),
          this.streamProgress.map((characters) => ({
            progress: { characters },
          })),
        );
      },
      streamInvestigateAudit: (call) => {
        this.callCounts.streamInvestigateAudit += 1;
        this.lastInvestigateAuditRequest = {
          question: call.request.question,
          retrievedContext: call.request.retrievedContext,
        };
        void this.stream(call, () => ({
          auditInvestigation: this.auditInvestigationResult,
        }));
      },
    };
    this.server.addService(AnalysisServiceService, impl);

    const port = await new Promise<number>((resolve, reject) => {
      this.server!.bindAsync(
        '127.0.0.1:0',
        grpc.ServerCredentials.createInsecure(),
        (error, boundPort) => (error ? reject(error) : resolve(boundPort)),
      );
    });
    return `127.0.0.1:${port}`;
  }

  private async stream(
    call: grpc.ServerWritableStream<unknown, AnalysisEvent>,
    result: () => AnalysisEvent,
    extra: AnalysisEvent[] = [],
  ): Promise<void> {
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
    let cancelled = false;
    call.on('cancelled', () => (cancelled = true));
    if (this.responseDelayMs > 0) await sleep(this.responseDelayMs);
    for (const progress of extra) {
      if (cancelled) return;
      call.write(progress);
    }
    for (const text of this.streamDeltas) {
      if (cancelled) return;
      call.write({ delta: { text } });
      if (this.streamGapMs > 0) await sleep(this.streamGapMs);
    }
    if (cancelled) return;
    if (this.streamFailsWith !== undefined) {
      call.emit('error', { code: this.streamFailsWith, details: 'fake' });
      return;
    }
    call.write(result());
    call.end();
  }

  private respond<T>(
    callback: (error: grpc.ServiceError | null, response: T) => void,
    getResult: () => T,
  ): void {
    if (this.responseDelayMs > 0) {
      setTimeout(() => callback(null, getResult()), this.responseDelayMs);
    } else {
      callback(null, getResult());
    }
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve) => {
      this.server?.tryShutdown(() => resolve());
    });
  }
}
