import * as grpc from '@grpc/grpc-js';
import {
  AnalysisServiceService,
  type AnalysisServiceServer,
  type DlpAnalysisResult,
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
  };

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
  dlpResult: DlpAnalysisResult = { findings: [], overallSeverity: 0 };

  async start(): Promise<string> {
    this.server = new grpc.Server();
    const impl: AnalysisServiceServer = {
      analyzeRisk: (_call, callback) => {
        this.callCounts.analyzeRisk += 1;
        this.respond(callback, () => this.riskResult);
      },
      analyzePromptInjection: (_call, callback) => {
        this.callCounts.analyzePromptInjection += 1;
        this.respond(callback, () => this.promptInjectionResult);
      },
      analyzeDlp: (_call, callback) => {
        this.callCounts.analyzeDlp += 1;
        this.respond(callback, () => this.dlpResult);
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
